// Copyright Drydock Contributors.
// Portions derived from containrrr/watchtower (Apache-2.0).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package updatereport

import (
	"context"
	"errors"
	"fmt"

	"github.com/containrrr/shoutrrr/pkg/router"
	"github.com/containrrr/shoutrrr/pkg/types"
)

// Router is the subset of shoutrrr's router that updatereport needs - the
// same minimal shape upstream's notifier programs against
// (pkg/notifications/shoutrrr.go:25-27). The cmd layer constructs the real
// router from --notification-url (e.g. via shoutrrr.NewSender,
// shoutrrr@v0.8.0/shoutrrr.go) and injects it here; this package never
// parses notification URLs itself.
type Router interface {
	Send(message string, params *types.Params) []error
}

// Compile-time proof that the router built by the cmd layer satisfies Router.
var _ Router = (*router.ServiceRouter)(nil)

// NewShoutrrrSender adapts a shoutrrr router into a Sender. The subject is
// carried as the shoutrrr title parameter (types.Params.SetTitle,
// pkg/types/params.go:14) and the body as the message.
func NewShoutrrrSender(r Router) Sender {
	return &shoutrrrSender{router: r}
}

// shoutrrrSender is the production Sender: a thin adapter over
// containrrr/shoutrrr v0.8.0 (upstream dependency, go.mod:6).
type shoutrrrSender struct {
	router Router
}

// Compile-time assertion required by the package spec; unit tests never
// construct a real shoutrrr router (no network, no URL parsing).
var _ Sender = (*shoutrrrSender)(nil)

// Send delivers one notification. shoutrrr v0.8 sends synchronously per URL
// and is not context-aware, so ctx is only honoured as a pre-send
// cancellation check. Per-URL errors are collapsed into a single error
// (errors.Join for more than one).
func (s *shoutrrrSender) Send(ctx context.Context, subject, body string) error {
	if s == nil || s.router == nil {
		return errors.New("updatereport: shoutrrr sender has no router")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("updatereport: send cancelled: %w", err)
	}
	params := types.Params{}
	params.SetTitle(subject)
	errs := s.router.Send(body, &params)
	var failures []error
	for _, err := range errs {
		if err != nil {
			failures = append(failures, err)
		}
	}
	switch len(failures) {
	case 0:
		return nil
	case 1:
		return failures[0]
	default:
		return errors.Join(failures...)
	}
}
