// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import (
	"net"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

const logSubsys = "fqdn"

// MarkDNSCTEntry records that dstIP is in use by a connection that is allowed
// by toFQDNs policy. The reverse lookup is attempted in both DNSHistory and
// DNSCTHistory, allowing short DNS TTLs but long-lived connections to
// persisthere.DNSCTHistory is used to suppress delete handling of expired DNS
// lookups (in DNSHistory) and it relies on pkg/maps/ctmap/gc to call this
// function.
// Internally, the lookupTime is used to checkpoint this update so that
// dns-garbage-collector-job can correctly clear older connection data.
func (e *Endpoint) MarkDNSCTEntry(dstIP net.IP, TTL time.Duration) {
	if dstIP == nil {
		e.Logger(logSubsys).Error("MarkDNSCTEntry called with nil IP")
		return
	}

	var (
		scopedLog  = e.Logger(logSubsys)
		lookupTime = time.Now()
		names      []string
	)
	// The DNS TTL may have expired, so use the DNS CT cache to roll forward a qname->IP mapping
	// TODO: This misses cases where a FQDN IP is allowed due to another
	// endpoint's lookup. Normally, that case is handled by pooling caches into
	// the daemon-global DNS cache.
	names = append(names, e.DNSCTHistory.LookupIP(dstIP)...)
	names = append(names, e.DNSHistory.LookupIP(dstIP)...)

	if len(names) == 0 {
		scopedLog.WithFields(logrus.Fields{
			logfields.IPAddr: dstIP,
		}).Warn("Could not update endpoint DNS CT cache with IP. No DNS match found in cache.")
		return
	}

	for _, qname := range names {
		e.Logger(logSubsys).WithFields(logrus.Fields{
			logfields.DNSName: qname,
			logfields.IPAddr:  dstIP,
		}).Debug("Updating ep DNS CT cache with qname->IP")
		e.DNSCTHistory.Update(lookupTime, qname, []net.IP{dstIP}, int(TTL.Seconds()))
	}

	e.SyncEndpointHeaderFile()
}

type DNSDelete struct {
	Qname           string
	IP              net.IP
	ActiveAt        time.Time
	DeletePendingAt time.Time
}

type DNSDeletes struct {
	lock.Mutex
	deletes        map[string][]*DNSDelete // map[ip]toDelete
	lastCTGCUpdate time.Time
}

// WantToDelete enqueues the ip -> qname as a possible deletion
// updatedExisting is true when an earlier enqueue existed and was updated
func (d *DNSDeletes) WantToDelete(ip net.IP, qname string) (updatedExisting bool) {
	d.Lock()
	defer d.Unlock()

	ipStr := ip.String()
	entry, updatedExisting := d.deletes[ipStr]
	if !updatedExisting {
		entry := &DNSDelete{}
		d.deletes[ipStr] = append(d.deletes[ipStr], entry)
	}

	entry.Qname = qname
	entry.IP = ip
	DeletePendingAt = time.Now()

	return updatedExisting
}

// Delete after it is seen by CT GC, DeletePendingAt < lastCTGCUpdate, and the ActiveTime is 0 or no longer current, ActiveAt < lastCTGCUpdate
func (d *DNSDeletes) canDelete(del *DNSDelete) bool {
	return d.lastGCUpdate.After(del.DeletePendingAt) && d.lastGCUpdate.After(del.ActiveAt)
}

func (d *DNSDeletes) ClearDeletable() (deletable []*DNSDelete) {
	d.Lock()
	defer d.Unlock()

	// Collect entries we can delete
perIP:
	for ipStr, dels := range d.deletes {
		for _, del := range dels {
			if !d.CanDelete(del) {
				continue perIP
			}
		}
		deletable = append(deletable, dels...)
	}

	// Delete the entries we collected above
	for _, del := range deletable {
		delete(d.deletes[del.IP.String()])
	}

	return deletable
}

func (d *DNSDeletes) MarkActive(ip net.IP, now time.Time) {
	d.Lock()
	defer d.Unlock()

	entries, exists := d.deletes[ip.String()]
	if !exists {
		return
	}
	for _, entry := range entries {
		entry.ActiveAt = now
	}
}

func (d *DNSDeletes) MarkGCTime(now time.Time) {
	d.lastCTGCUpdate = now
}
