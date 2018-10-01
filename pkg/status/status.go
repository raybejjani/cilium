// Copyright 2018 Authors of Cilium
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

package status

import (
	"context"
	"fmt"
	"time"
)

const (
	defaultInterval         = 5 * time.Second
	defaultFailureThreshold = time.Minute
	defaultWarningThreshold = 20 * time.Second
)

type Status struct {
	// Data is non-nil when the probe has completed successfully. Data is
	// set to the value returned by Probe()
	Data interface{}

	// Error is non-nil if either the probe file or the Failure or Warning
	// threshold has been reached
	Err error

	// StaleWarning is true once the WarningThreshold has been reached
	StaleWarning bool
}

type Probe struct {
	Name string

	Probe func(ctx context.Context) (interface{}, error)

	// Status is called whenever the status of the probe changes
	Status func(status Status)
}

type Collector struct {
	config Configuration
	stop   chan struct{}
}

type Configuration struct {
	WarningThreshold time.Duration
	FailureThreshold time.Duration
	Interval         time.Duration
}

func NewCollector(probes []Probe, config Configuration) *Collector {
	c := &Collector{
		config: config,
		stop:   make(chan struct{}, 0),
	}

	if c.config.Interval == time.Duration(0) {
		c.config.Interval = defaultInterval
	}

	if c.config.FailureThreshold == time.Duration(0) {
		c.config.FailureThreshold = defaultFailureThreshold
	}

	if c.config.WarningThreshold == time.Duration(0) {
		c.config.WarningThreshold = defaultWarningThreshold
	}

	for _, probe := range probes {
		go c.runBackgroundProbe(&probe)
	}

	return c
}

// Close exits all probes and shuts down the collector
func (c *Collector) Close() {
	close(c.stop)
}

// runBackgroundProbe continuously calls Probe() and Status(), waiting for the
// defined interval between invocations, until Collector.Close() is called.
// Probe() is called without wait on the when first calling this function.
func (c *Collector) runBackgroundProbe(p *Probe) {
	go func() {
		for {
			c.runProbe(p)

			select {
			case <-c.stop:
				// collector is closed, stop looping
				return
			case <-time.After(c.config.Interval):
				// keep looping
			}
		}
	}()
}

// runProbe runs Probe() once and, on success, Status(). runProbe returns after
// FailureThreshold elapses and calls Status() with no data and an error.  An
// error is included when the probe took longer than WarningThreshold to
// return.
func (c *Collector) runProbe(p *Probe) {
	for {
		var (
			statusData       interface{}
			err              error
			warningThreshold = time.After(c.config.WarningThreshold)
			hardTimeout      = false
			probeReturned    = make(chan struct{}, 1)
			ctx, cancel      = context.WithTimeout(context.Background(), c.config.FailureThreshold)
		)

		go func() {
			statusData, err = p.Probe(ctx)
			close(probeReturned)
		}()

		// This is a loop so that, when we hit a FailureThreshold, we still do
		// not return until the probe returns. This is to ensure the same probe
		// does not run again while it is blocked.
		for {
			select {
			case <-c.stop:
				// Collector was closed. The probe will
				// complete in the background and won't be
				// restarted again.
				cancel()
				return

			case <-warningThreshold:
				// Publish warning and continue waiting for probe
				p.Status(Status{
					Err:          fmt.Errorf("No response from %s probe within %f seconds", p.Name, c.config.WarningThreshold.Seconds()),
					StaleWarning: true,
				})

			case <-probeReturned:
				// The probe completed and we can return from runProbe
				switch {
				case hardTimeout:
					// FailureThreshold was already
					// reached. Keep the failure error
					// message
				case err != nil:
					p.Status(Status{Err: err})
				default:
					p.Status(Status{Data: statusData})
				}

				cancel()
				return

			case <-ctx.Done():
				// We have timed out. Report a status and mark that we timed out so we
				// do not emit status later.
				p.Status(Status{
					Err:          fmt.Errorf("No response from %s probe within %f seconds", p.Name, c.config.WarningThreshold.Seconds()),
					StaleWarning: true,
				})
				hardTimeout = true
			}
		}
	}
}
