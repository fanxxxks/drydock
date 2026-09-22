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
	"testing"
	"time"

	"github.com/containrrr/shoutrrr/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRouter is the capturing stand-in for a shoutrrr ServiceRouter. It never
// parses URLs and never dials anything: the only shoutrrr surface it touches
// is types.Params, an in-memory map. This is the injection seam that keeps
// the package's delivery path testable without a network.
type fakeRouter struct {
	calls   []routerCall
	retErrs []error
}

type routerCall struct {
	message string
	title   string
}

func (f *fakeRouter) Send(message string, params *types.Params) []error {
	call := routerCall{message: message}
	if params != nil {
		call.title, _ = params.Title()
	}
	f.calls = append(f.calls, call)
	return f.retErrs
}

var _ Router = (*fakeRouter)(nil)

func TestShoutrrrSenderSend(t *testing.T) {
	errTelegram := errors.New("telegram: 400 bad request")
	errDiscord := errors.New("discord: 429 too many requests")

	cases := []struct {
		name         string
		sender       func() Sender
		ctx          func() context.Context
		routerErrs   []error
		wantErrIs    []error
		wantErrText  []string
		wantRouter   bool
		wantTitle    string
		wantMessage  string
	}{
		{
			name: "nil sender receiver is an error, not a panic",
			sender: func() Sender { var s *shoutrrrSender; return s },
			ctx:   func() context.Context { return context.Background() },
			wantErrText: []string{"updatereport: shoutrrr sender has no router"},
			wantRouter:  false,
		},
		{
			name: "nil router is an error, not a panic",
			sender: func() Sender { return NewShoutrrrSender(nil) },
			ctx:   func() context.Context { return context.Background() },
			wantErrText: []string{"updatereport: shoutrrr sender has no router"},
			wantRouter:  false,
		},
		{
			name: "cancelled context aborts before the router is touched",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErrIs:  []error{context.Canceled},
			wantRouter: false,
		},
		{
			name: "already-expired deadline aborts before the router is touched",
			ctx: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), -time.Second)
				cancel()
				return ctx
			},
			wantErrIs:  []error{context.DeadlineExceeded},
			wantRouter: false,
		},
		{
			name:        "all urls delivered: nil error, subject carried as title",
			ctx:         func() context.Context { return context.Background() },
			wantRouter:  true,
			wantTitle:   "drydock: 1 updated",
			wantMessage: "cycle body",
		},
		{
			name:       "single per-url failure propagates that error",
			ctx:        func() context.Context { return context.Background() },
			routerErrs: []error{errTelegram},
			wantErrIs:  []error{errTelegram},
			wantRouter: true,
		},
		{
			name:       "multiple per-url failures are joined and each is reachable via errors.Is",
			ctx:        func() context.Context { return context.Background() },
			routerErrs: []error{errTelegram, errDiscord},
			wantErrIs:  []error{errTelegram, errDiscord},
			wantRouter: true,
		},
		{
			name:       "nil entries in the per-url error slice are filtered",
			ctx:        func() context.Context { return context.Background() },
			routerErrs: []error{nil, errTelegram, nil},
			wantErrIs:  []error{errTelegram},
			wantRouter: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRouter{retErrs: tc.routerErrs}
			// Every case that exercises a real router path is wired to the
			// instrumented fr; only the nil-sender/nil-router cases build
			// their own (invalid) sender via the closure.
			var s Sender
			if tc.sender != nil {
				s = tc.sender()
			} else {
				s = NewShoutrrrSender(fr)
			}

			subject := tc.wantTitle
			if subject == "" {
				subject = "drydock: 1 updated"
			}
			body := tc.wantMessage
			if body == "" {
				body = "cycle body"
			}

			err := s.Send(tc.ctx(), subject, body)

			if len(tc.wantErrIs) == 0 && len(tc.wantErrText) == 0 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				for _, want := range tc.wantErrIs {
					assert.ErrorIs(t, err, want)
				}
				for _, want := range tc.wantErrText {
					assert.Contains(t, err.Error(), want)
				}
			}

			if !tc.wantRouter {
				assert.Empty(t, fr.calls, "router must not be touched")
				return
			}
			require.Len(t, fr.calls, 1)
			assert.Equal(t, subject, fr.calls[0].title, "subject travels as the shoutrrr title param")
			assert.Equal(t, body, fr.calls[0].message, "body travels as the message")
		})
	}
}

func TestShoutrrrSenderEmptyErrorSliceIsSuccess(t *testing.T) {
	fr := &fakeRouter{retErrs: []error{}}
	s := NewShoutrrrSender(fr)

	require.NoError(t, s.Send(context.Background(), "subj", "body"))
	require.Len(t, fr.calls, 1)
}

// TestShoutrrrSenderViaReporter exercises the production Sender behind the
// full Reporter flow: silence rule, subject line and body routing, and the
// swallow rule for delivery failures - all through fakes.
func TestShoutrrrSenderViaReporter(t *testing.T) {
	t.Run("quiet cycle never reaches the router", func(t *testing.T) {
		fr := &fakeRouter{}
		r, console := newTestReporter(NewShoutrrrSender(fr))

		require.NoError(t, r.Report(context.Background(), quietCycle()))

		assert.Empty(t, fr.calls, "silence rule applies to the production sender too")
		assert.Contains(t, console.String(), "drydock: no changes")
	})

	t.Run("notifiable cycle routes subject and rendered body", func(t *testing.T) {
		fr := &fakeRouter{}
		r, _ := newTestReporter(NewShoutrrrSender(fr))

		require.NoError(t, r.Report(context.Background(), rollbackCycle()))

		require.Len(t, fr.calls, 1)
		assert.Equal(t, "drydock: 1 failed, 1 rolled back", fr.calls[0].title)
		assert.Contains(t, fr.calls[0].message, "api")
		assert.Contains(t, fr.calls[0].message, "restored from snapshot api-1726920000000000000")
	})

	t.Run("router failures are logged and swallowed by Report", func(t *testing.T) {
		fr := &fakeRouter{retErrs: []error{
			errors.New("telegram: connect refused"),
			errors.New("discord: 429"),
		}}
		r, console := newTestReporter(NewShoutrrrSender(fr))

		var err error
		require.NotPanics(t, func() { err = r.Report(context.Background(), updatedCycle()) })

		require.NoError(t, err, "delivery failure must not surface as a Report error")
		require.Len(t, fr.calls, 1, "the send was attempted")
		assert.Contains(t, console.String(), "drydock: 1 updated", "console summary still written")
	})
}
