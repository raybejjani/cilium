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

	"github.com/cilium/cilium/pkg/lock"
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

	e.DNSDeletes.MarkActive(dstIP, time.Now())
	e.SyncEndpointHeaderFile()
}

type DNSDelete struct {
	Names           []string
	IP              net.IP
	ActiveAt        time.Time
	DeletePendingAt time.Time
}

type DNSDeletes struct {
	lock.Mutex
	deletes        map[string]*DNSDelete // map[ip]toDelete
	lastCTGCUpdate time.Time
}

func NewDNSDeletes() *DNSDeletes {
	return &DNSDeletes{
		deletes: make(map[string]*DNSDelete),
	}
}

// WantToDelete enqueues the ip -> qname as a possible deletion
// updatedExisting is true when an earlier enqueue existed and was updated
func (d *DNSDeletes) WantToDelete(ipStr string, qname ...string) (updatedExisting bool) {
	d.Lock()
	defer d.Unlock()

	entry, updatedExisting := d.deletes[ipStr]
	if !updatedExisting {
		entry = &DNSDelete{}
		d.deletes[ipStr] = entry
	}

	entry.Names = append(entry.Names, qname...)
	entry.IP = net.ParseIP(ipStr)
	entry.DeletePendingAt = time.Now()

	return updatedExisting
}

// Delete after it is seen by CT GC, DeletePendingAt < lastCTGCUpdate, and the ActiveTime is 0 or no longer current, ActiveAt < lastCTGCUpdate
func (d *DNSDeletes) canDelete(del *DNSDelete) bool {
	return d.lastCTGCUpdate.After(del.DeletePendingAt) && d.lastCTGCUpdate.After(del.ActiveAt)
}

func (d *DNSDeletes) ClearDeletable() (active, deletable []*DNSDelete) {
	d.Lock()
	defer d.Unlock()

	// Collect entries we can delete
perIP:
	for _, del := range d.deletes {
		cpy := &DNSDelete{
			IP:              del.IP,
			DeletePendingAt: del.DeletePendingAt,
			ActiveAt:        del.ActiveAt,
		}
		cpy.Names = append(cpy.Names, del.Names...)

		if !d.canDelete(cpy) {
			active = append(active, cpy)
			continue perIP
		}
		deletable = append(deletable, cpy)
	}

	// Delete the entries we collected above
	for _, del := range deletable {
		delete(d.deletes, del.IP.String())
	}

	return active, deletable
}

func (d *DNSDeletes) MarkActive(ip net.IP, now time.Time) {
	d.Lock()
	defer d.Unlock()

	entry, exists := d.deletes[ip.String()]
	if !exists {
		return
	}
	entry.ActiveAt = now
}

func (d *DNSDeletes) MarkGCTime(now time.Time) {
	d.lastCTGCUpdate = now
}
