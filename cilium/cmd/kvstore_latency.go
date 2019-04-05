// Copyright 2019 Authors of Cilium
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

package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/kvstore"

	"github.com/spf13/cobra"
)

const (
	tsFormat      = time.RFC3339Nano
	defaultKey    = "testkey"
	defaultPrefix = "/cilium/testprop/"
)

var (
	watchPrefix string
	modifyKey   string
)

var kvstoreTestCmd = &cobra.Command{
	Use:     "test [options]",
	Short:   "Test propagation delay",
	Example: "cilium kvstore test",
	Run: func(cmd *cobra.Command, args []string) {
		setupKvstore()

		go watch(watchPrefix)

		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
		for {
			time.Sleep(1 * time.Second)
			select {
			case <-c:
				return
			default:
				value := time.Now().Format(tsFormat)
				err := kvstore.Set(modifyKey, []byte(value))
				if err != nil {
					Fatalf("Unable to set key: %s", err)
				}
			}
		}
	},
}

func init() {
	kvstoreCmd.AddCommand(kvstoreTestCmd)
	flags := kvstoreCmd.PersistentFlags()

	flags.StringVar(&watchPrefix, "watch-prefix", defaultPrefix, "prefix to watch")
	flags.StringVar(&modifyKey, "key-name", defaultPrefix+defaultKey, "key to create")
}

func watch(prefix string) {
	fmt.Printf("Starting to read events\n")
	defer fmt.Printf("Stopping reading events\n")

	watcher := kvstore.ListAndWatch("", prefix, 10)
	defer watcher.Stop()

	for e := range watcher.Events {
		since := time.Duration(0)
		timeVal := string(e.Value)
		t, err := time.Parse(tsFormat, timeVal)
		if err != nil {
			fmt.Printf("Error parsing key value: %v -> %v\n", e.Value, err)
		} else {
			since = time.Since(t)
		}
		fmt.Printf("Event seen. Type: %v, key: %v, value: %s, delay: %s\n", e.Typ, e.Key, timeVal, since)
	}
}
