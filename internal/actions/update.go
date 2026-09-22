package actions

import (
	"context"
	"errors"

	"github.com/drydock-updater/drydock/internal/util"
	"github.com/drydock-updater/drydock/pkg/container"
	"github.com/drydock-updater/drydock/pkg/lifecycle"
	"github.com/drydock-updater/drydock/pkg/safeflow"
	"github.com/drydock-updater/drydock/pkg/session"
	"github.com/drydock-updater/drydock/pkg/sorter"
	"github.com/drydock-updater/drydock/pkg/types"
	log "github.com/sirupsen/logrus"
)

// Update looks at the running Docker containers to see if any of the images
// used to start those containers have been updated. If a change is detected in
// any of the images, the associated containers are stopped and restarted with
// the new image.
//
// Drydock safety loop: when params.Safety is wired (cmd layer), the flow
// becomes precheck -> snapshot -> (upstream stop/recreate) -> health gate ->
// rollback; a nil params.Safety keeps the exact upstream watchtower
// behavior. The safeflow view of the cycle is accumulated into
// params.Safety.Cycle for the cycle reporter.
func Update(client container.Client, params types.UpdateParams) (types.Report, error) {
	log.Debug("Checking containers for updated images")
	progress := &session.Progress{}
	staleCount := 0
	ctx := context.Background()

	if params.LifecycleHooks {
		lifecycle.ExecutePreChecks(client, params)
	}

	containers, err := client.ListContainers(params.Filter)
	if err != nil {
		return nil, err
	}

	staleCheckFailed := 0
	// Drydock safety loop: containers whose update the policy gate vetoed.
	// They are left completely untouched (not even marked for update, which
	// would overwrite their skipped session state).
	vetoed := make(map[types.ContainerID]bool)

	for i, targetContainer := range containers {
		stale, newestImage, err := client.IsContainerStale(targetContainer, params)
		shouldUpdate := stale && !params.NoRestart && !targetContainer.IsMonitorOnly(params)
		if err == nil && shouldUpdate {
			// Check to make sure we have all the necessary information for recreating the container
			err = targetContainer.VerifyConfiguration()
			// If the image information is incomplete and trace logging is enabled, log it for further diagnosis
			if err != nil && log.IsLevelEnabled(log.TraceLevel) {
				imageInfo := targetContainer.ImageInfo()
				log.Tracef("Image info: %#v", imageInfo)
				log.Tracef("Container info: %#v", targetContainer.ContainerInfo())
				if imageInfo != nil {
					log.Tracef("Image config: %#v", imageInfo.Config)
				}
			}
		}

		// Drydock safety loop stage 1: the pre-update policy gate. It runs
		// after staleness has been decided (the newest image is already
		// pulled and its inspect is local) and before the container is
		// marked for update. A veto leaves the container untouched this
		// cycle and records the reason.
		var verdict *safeflow.PrecheckVerdict
		if err == nil && shouldUpdate && params.Safety.PrecheckActive() {
			v, veto := runPrecheck(ctx, client, params.Safety, targetContainer)
			verdict = &v
			if veto != nil {
				log.Infof("Drydock precheck vetoed updating %q: %v", targetContainer.Name(), veto)
				stale = false
				vetoed[targetContainer.ID()] = true
				progress.AddSkipped(targetContainer, veto)
				entry := cycleEntry(params.Safety, targetContainer)
				entry.Precheck = verdict
				entry.Status = safeflow.StatusSkipped
			}
		}

		if err != nil {
			log.Infof("Unable to update container %q: %v. Proceeding to next.", targetContainer.Name(), err)
			stale = false
			staleCheckFailed++
			progress.AddSkipped(targetContainer, err)
			if params.Safety != nil {
				cycleEntry(params.Safety, targetContainer).Status = safeflow.StatusSkipped
			}
		} else if !vetoed[targetContainer.ID()] {
			progress.AddScanned(targetContainer, newestImage)
			if params.Safety != nil {
				entry := cycleEntry(params.Safety, targetContainer)
				entry.Precheck = verdict
				if stale {
					entry.NewImageRef = targetContainer.ImageName()
				} else {
					entry.Status = safeflow.StatusFresh
				}
			}
		}
		containers[i].SetStale(stale)

		if stale {
			staleCount++
		}
	}

	containers, err = sorter.SortByDependencies(containers)
	if err != nil {
		return nil, err
	}

	UpdateImplicitRestart(containers)

	var containersToUpdate []types.Container
	for _, c := range containers {
		if !c.IsMonitorOnly(params) && !vetoed[c.ID()] {
			containersToUpdate = append(containersToUpdate, c)
			progress.MarkForUpdate(c.ID())
		}
	}

	// Drydock safety loop stage 2: snapshot every container that is about to
	// be stopped and recreated, before any stop or rolling restart happens.
	var snaps map[types.ContainerID]safeflow.Snapshot
	if params.Safety != nil {
		snaps = takeSafetySnapshots(ctx, params.Safety, containersToUpdate)
	}

	if params.RollingRestart {
		progress.UpdateFailed(performRollingRestart(containersToUpdate, client, params, snaps))
	} else {
		failedStop, stoppedImages := stopContainersInReversedOrder(containersToUpdate, client, params)
		progress.UpdateFailed(failedStop)
		failedStart := restartContainersInSortedOrder(containersToUpdate, client, params, stoppedImages, snaps)
		progress.UpdateFailed(failedStart)
	}

	if params.LifecycleHooks {
		lifecycle.ExecutePostChecks(client, params)
	}

	// Containers that were watched but never recreated this cycle (global
	// no-restart, monitor-only, lifecycle exit-code-75 skips) are left
	// untouched, which the safeflow report expresses as skipped.
	if params.Safety != nil && params.Safety.Cycle != nil {
		for i := range params.Safety.Cycle.Updates {
			if params.Safety.Cycle.Updates[i].Status == "" {
				params.Safety.Cycle.Updates[i].Status = safeflow.StatusSkipped
			}
		}
	}

	return progress.Report(), nil
}

func performRollingRestart(containers []types.Container, client container.Client, params types.UpdateParams, snaps map[types.ContainerID]safeflow.Snapshot) map[types.ContainerID]error {
	cleanupImageIDs := make(map[types.ImageID]bool, len(containers))
	failed := make(map[types.ContainerID]error, len(containers))

	for i := len(containers) - 1; i >= 0; i-- {
		if containers[i].ToRestart() {
			err := stopStaleContainer(containers[i], client, params)
			if err != nil {
				failed[containers[i].ID()] = err
			} else {
				if err := restartStaleContainer(containers[i], client, params, snaps); err != nil {
					failed[containers[i].ID()] = err
				} else if containers[i].IsStale() {
					// Only add (previously) stale containers' images to cleanup
					cleanupImageIDs[containers[i].ImageID()] = true
				}
			}
		}
	}

	if params.Cleanup {
		cleanupImages(client, cleanupImageIDs)
	}
	return failed
}

func stopContainersInReversedOrder(containers []types.Container, client container.Client, params types.UpdateParams) (failed map[types.ContainerID]error, stopped map[types.ImageID]bool) {
	failed = make(map[types.ContainerID]error, len(containers))
	stopped = make(map[types.ImageID]bool, len(containers))
	for i := len(containers) - 1; i >= 0; i-- {
		if err := stopStaleContainer(containers[i], client, params); err != nil {
			failed[containers[i].ID()] = err
		} else {
			// NOTE: If a container is restarted due to a dependency this might be empty
			stopped[containers[i].SafeImageID()] = true
		}

	}
	return
}

func stopStaleContainer(container types.Container, client container.Client, params types.UpdateParams) error {
	if container.IsWatchtower() {
		log.Debugf("This is the watchtower container %s", container.Name())
		return nil
	}

	if !container.ToRestart() {
		return nil
	}

	// Perform an additional check here to prevent us from stopping a linked container we cannot restart
	if container.IsLinkedToRestarting() {
		if err := container.VerifyConfiguration(); err != nil {
			markCycleFailed(params.Safety, container, err)
			return err
		}
	}

	if params.LifecycleHooks {
		skipUpdate, err := lifecycle.ExecutePreUpdateCommand(client, container)
		if err != nil {
			log.Error(err)
			log.Info("Skipping container as the pre-update command failed")
			markCycleFailed(params.Safety, container, err)
			return err
		}
		if skipUpdate {
			log.Debug("Skipping container as the pre-update command returned exit code 75 (EX_TEMPFAIL)")
			markCycleSkipped(params.Safety, container)
			return errors.New("skipping container as the pre-update command returned exit code 75 (EX_TEMPFAIL)")
		}
	}

	if err := client.StopContainer(container, params.Timeout); err != nil {
		log.Error(err)
		markCycleFailed(params.Safety, container, err)
		return err
	}
	return nil
}

func restartContainersInSortedOrder(containers []types.Container, client container.Client, params types.UpdateParams, stoppedImages map[types.ImageID]bool, snaps map[types.ContainerID]safeflow.Snapshot) map[types.ContainerID]error {
	cleanupImageIDs := make(map[types.ImageID]bool, len(containers))
	failed := make(map[types.ContainerID]error, len(containers))

	for _, c := range containers {
		if !c.ToRestart() {
			continue
		}
		if stoppedImages[c.SafeImageID()] {
			if err := restartStaleContainer(c, client, params, snaps); err != nil {
				failed[c.ID()] = err
			} else if c.IsStale() {
				// Only add (previously) stale containers' images to cleanup
				cleanupImageIDs[c.ImageID()] = true
			}
		}
	}

	if params.Cleanup {
		cleanupImages(client, cleanupImageIDs)
	}

	return failed
}

func cleanupImages(client container.Client, imageIDs map[types.ImageID]bool) {
	for imageID := range imageIDs {
		if imageID == "" {
			continue
		}
		if err := client.RemoveImageByID(imageID); err != nil {
			log.Error(err)
		}
	}
}

func restartStaleContainer(container types.Container, client container.Client, params types.UpdateParams, snaps map[types.ContainerID]safeflow.Snapshot) error {
	// Since we can't shutdown a watchtower container immediately, we need to
	// start the new one while the old one is still running. This prevents us
	// from re-using the same container name so we first rename the current
	// instance so that the new one can adopt the old name.
	if container.IsWatchtower() {
		if err := client.RenameContainer(container, util.RandName()); err != nil {
			log.Error(err)
			return nil
		}
	}

	if !params.NoRestart {
		newContainerID, err := client.StartContainer(container)
		if err != nil {
			log.Error(err)
			if params.Safety != nil {
				entry := cycleEntry(params.Safety, container)
				entry.Status = safeflow.StatusFailed
				entry.Error = err.Error()
				entry.NewImageRef = container.ImageName()
			}
			return err
		}

		// Drydock safety loop stages 4+5: gate the freshly created
		// replacement (and roll it back when unhealthy) BEFORE the
		// post-update hooks and before any image cleanup, so a rolled-back
		// container never has its old image removed from under it.
		if params.Safety != nil {
			entry := cycleEntry(params.Safety, container)
			if gateErr := gateReplacement(params.Safety, container, string(newContainerID), snaps, entry); gateErr != nil {
				return gateErr
			}
			if entry.Status == "" {
				entry.Status = safeflow.StatusUpdated
				entry.NewImageRef = container.ImageName()
			}
		}

		if container.ToRestart() && params.LifecycleHooks {
			lifecycle.ExecutePostUpdateCommand(client, newContainerID)
		}
	}
	return nil
}

// UpdateImplicitRestart iterates through the passed containers, setting the
// `LinkedToRestarting` flag if any of it's linked containers are marked for restart
func UpdateImplicitRestart(containers []types.Container) {

	for ci, c := range containers {
		if c.ToRestart() {
			// The container is already marked for restart, no need to check
			continue
		}

		if link := linkedContainerMarkedForRestart(c.Links(), containers); link != "" {
			log.WithFields(log.Fields{
				"restarting": link,
				"linked":     c.Name(),
			}).Debug("container is linked to restarting")
			// NOTE: To mutate the array, the `c` variable cannot be used as it's a copy
			containers[ci].SetLinkedToRestarting(true)
		}

	}
}

// linkedContainerMarkedForRestart returns the name of the first link that matches a
// container marked for restart
func linkedContainerMarkedForRestart(links []string, containers []types.Container) string {
	for _, linkName := range links {
		for _, candidate := range containers {
			if candidate.Name() == linkName && candidate.ToRestart() {
				return linkName
			}
		}
	}
	return ""
}
