package types

import (
	"time"
)

// UpdateParams contains all different options available to alter the behavior of the Update func
type UpdateParams struct {
	Filter          Filter
	Cleanup         bool
	NoRestart       bool
	Timeout         time.Duration
	MonitorOnly     bool
	NoPull			bool
	LifecycleHooks  bool
	RollingRestart  bool
	LabelPrecedence bool
	// Safety carries Drydock's update safety loop (precheck -> snapshot ->
	// update -> health gate -> rollback). Nil keeps the exact upstream
	// watchtower behavior.
	Safety *SafetyLoop
}
