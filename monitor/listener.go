// Copyright 2017 Authors of Cilium
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

package main

import (
	"encoding/gob"
	"net"
	"os"
	"syscall"

	"github.com/cilium/cilium/monitor/payload"
)

// monitorListener is a generic consumer of monitor events. Implementers are
// expected to handle errors as needed, including exiting.
type monitorListener interface {
	// Enqueue adds this payload to the send queue. Any errors should be logged
	// and handled appropriately.
	Enqueue(pl *payload.Payload)
}

// listenerv1_0 implements the ciliim-node-monitor API protocol compatible with
// cilium 1.0
// cleanupFn is called on exit
type listenerv1_0 struct {
	conn      net.Conn
	queue     chan *payload.Payload
	cleanupFn func(monitorListener)
}

func newListenerv1_0(c net.Conn, queueSize int, cleanupFn func(monitorListener)) *listenerv1_0 {
	ml := &listenerv1_0{
		conn:      c,
		queue:     make(chan *payload.Payload, queueSize),
		cleanupFn: cleanupFn,
	}

	go ml.drainQueue()

	return ml
}

func (ml *listenerv1_0) Enqueue(pl *payload.Payload) {
	select {
	case ml.queue <- pl:
	default:
		log.Debugf("Per listener queue is full, dropping message")
	}
}

// drainQueue encodes and sends monitor payloads to the listener. It is
// intended to be a goroutine.
func (ml *listenerv1_0) drainQueue() {
	defer func() {
		ml.conn.Close()
		ml.cleanupFn(ml)
	}()

	enc := gob.NewEncoder(ml.conn)
	for pl := range ml.queue {
		if err := pl.EncodeBinary(enc); err != nil {
			if op, ok := err.(*net.OpError); ok {
				if syscerr, ok := op.Err.(*os.SyscallError); ok {
					if errn, ok := syscerr.Err.(syscall.Errno); ok {
						if errn == syscall.EPIPE {
							log.Info("Listener disconnected")
							return
						}
					}
				}
			}
			log.WithError(err).Warn("Removing listener due to write failure")
			return
		}
	}
}

// listenerv1_2 implements the ciliim-node-monitor API protocol compatible with
// cilium 1.2
// cleanupFn is called on exit
type listenerv1_2 struct {
	conn      net.Conn
	queue     chan *payload.Payload
	cleanupFn func(monitorListener)
}

func newListenerv1_2(c net.Conn, queueSize int, cleanupFn func(monitorListener)) *listenerv1_2 {
	ml := &listenerv1_2{
		conn:      c,
		queue:     make(chan *payload.Payload, queueSize),
		cleanupFn: cleanupFn,
	}

	go ml.drainQueue()

	return ml
}

func (ml *listenerv1_2) Enqueue(pl *payload.Payload) {
	select {
	case ml.queue <- pl:
	default:
		log.Debugf("Per listener queue is full, dropping message")
	}
}

// drainQueue encodes and sends monitor payloads to the listener. It is
// intended to be a goroutine.
func (ml *listenerv1_2) drainQueue() {
	defer func() {
		ml.conn.Close()
		ml.cleanupFn(ml)
	}()

	enc := gob.NewEncoder(ml.conn)
	for pl := range ml.queue {
		if err := pl.EncodeBinary(enc); err != nil {
			if op, ok := err.(*net.OpError); ok {
				if syscerr, ok := op.Err.(*os.SyscallError); ok {
					if errn, ok := syscerr.Err.(syscall.Errno); ok {
						if errn == syscall.EPIPE {
							log.Info("Listener disconnected")
							return
						}
					}
				}
			}
			log.WithError(err).Warn("Removing listener due to write failure")
			return
		}
	}
}
