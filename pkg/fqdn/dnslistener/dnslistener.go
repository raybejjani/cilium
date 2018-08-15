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

package dnslistener

import (
	"context"
	"encoding/gob"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/monitor/listener"
	"github.com/cilium/cilium/monitor/payload"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/readdns"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/google/gopacket/layers"
)

var Listener = DNSListener{cache: fqdn.DefaultDNSCache}

type DNSListener struct {
	cacheLock lock.Mutex
	cache     *fqdn.DNSCache
}

func StartDNSListener() error {
	conn, version, err := openMonitorSock()
	if err != nil {
		return fmt.Errorf("Cannot open monitor socket: %s", err.Error())
	}

	if version != listener.Version1_2 {
		return fmt.Errorf("Unsupported monitor version %s", version)
	}

	go Listener.listenForDNSPackets(context.Background(), conn)

	return nil
}

// get rid of this?
func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// goroutine
// read from conn, dissect, write to packets
// exit on error, closing packets
func readMonitorDNSPackets(ctx context.Context, conn net.Conn, packets chan *readdns.Dissection) {
	// dissect
	// check for packet type
	// send if DNS
	defer close(packets)

	dec := gob.NewDecoder(conn)
	pl := payload.Payload{}

	for {
		err := pl.DecodeBinary(dec)
		switch {
		case isDone(ctx):
			// exit silently
			log.WithError(ctx.Err()).Debug("DNSListener no longer reading monitor packets due to context done")
			return

		case err != nil:
			log.WithError(err).Error("DNSListener no longer reading monitor packets due to error")
			return
		}

		//log.Info("DNSListener looking at packet")

		// check that this is a capture
		data := getRelevantDataSlice(pl.Data)
		if data == nil {
			//log.Info("DNSListener skipping packet of incorrect type")
			continue
		}

		// dissect packet
		// if DNS send it
		//log.Info("DNSListener reading packet")
		dissection, err := readDNS(data)
		switch {
		case err != nil:
			//log.WithError(err).Error("DNSListener skipping packet")
			continue

		case dissection == nil:
			//log.Info("DNSListener skipping because empty packet dissect")
			continue

		case dissection.DNS.QDCount == 0:
			//log.Info("DNSListener skipping because no DNS questions")
			continue

		default:
			log.Info("DNSListener passing packet along")
			packets <- dissection
		}
	}
}

// goroutine
func (l *DNSListener) listenForDNSPackets(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// packets from readMonitorPackets, closed to indicate errors
	packets := make(chan *readdns.Dissection, 1024)
	readerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go readMonitorDNSPackets(readerCtx, conn, packets)

	var packet *readdns.Dissection
	for !isDone(ctx) {
		select {
		case <-ctx.Done():
			return

		case p, ok := <-packets:
			if !ok {
				return
			}
			packet = p
		}

		//log.Infof("DNS Packet %#v", packet)

		// only read responses
		if !packet.DNS.QR {
			log.Infof("DNS Query ID %d for %s from %s", packet.DNS.ID, string(packet.DNS.Questions[0].Name), packet.IPv4.SrcIP.String())
			continue
		}

		// put all IPs into cache

		log.Infof("DNS Response ID %d for %s's %s query with %d answers from %s", packet.DNS.ID, packet.IPv4.DstIP.String(), string(packet.DNS.Questions[0].Name), packet.DNS.ANCount, packet.IPv4.SrcIP.String())
		ips := make([]net.IP, 0)
		ttl := 0
		for i := range packet.DNS.Answers {
			if packet.DNS.Answers[i].Type != layers.DNSTypeA || packet.DNS.Answers[i].Type != layers.DNSTypeAAAA {
				ips = append(ips, packet.DNS.Answers[i].IP)
				ttl = int(packet.DNS.Answers[i].TTL)
			}
			log.Infof("Inserting DNS Response %s -> %s into cache (query by %s)", packet.DNS.Answers[i].IP.String(), string(packet.DNS.Questions[0].Name), packet.IPv4.DstIP.String())
		}
		l.cache.Update(time.Now(), string(packet.DNS.Questions[0].Name), ips, ttl)
	}
}

// the payload is offset in the data based on the type of message
func getRelevantDataSlice(data []byte) []byte {
	messageType := data[0]

	switch messageType {
	case monitor.MessageTypeDrop:
		return data[monitor.DropNotifyLen:]

	case monitor.MessageTypeDebug:
		return data[monitor.DebugCaptureLen:]

	case monitor.MessageTypeTrace:
		return data[monitor.TraceNotifyLen:]

	case monitor.MessageTypeCapture, monitor.MessageTypeAccessLog, monitor.MessageTypeAgent:
		fallthrough
	default:
		return nil
	}
}

func readDNS(data []byte) (*readdns.Dissection, error) {
	dissect, _, err := readdns.GetDissect(data)
	switch {
	case err != nil && !strings.Contains(err.Error(), "No decoder for layer type"):
		return nil, nil

	case err != nil:
		return nil, err

	// case len(decoded) != 4: ?

	case dissect == nil, dissect.DNS.QDCount == 0:
		return nil, nil

	default:
		return dissect, nil
	}
}

// openMonitorSock attempts to open a version specific monitor socket It
// returns a connection, with a version, or an error.
func openMonitorSock() (conn net.Conn, version listener.Version, err error) {
	errors := make([]string, 0)

	// try the 1.2 socket
	conn, err = net.Dial("unix", defaults.MonitorSockPath1_2)
	if err == nil {
		return conn, listener.Version1_2, nil
	}
	errors = append(errors, defaults.MonitorSockPath1_2+": "+err.Error())

	// try the 1.1 socket
	conn, err = net.Dial("unix", defaults.MonitorSockPath1_0)
	if err == nil {
		return conn, listener.Version1_0, nil
	}
	errors = append(errors, defaults.MonitorSockPath1_0+": "+err.Error())

	return nil, listener.VersionUnsupported, fmt.Errorf("Cannot find or open a supported node-monitor socket. %s", strings.Join(errors, ","))
}
