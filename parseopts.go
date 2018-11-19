// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dhcp4

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

func parseDHCPDuration(b []byte) time.Duration {
	return time.Duration(binary.BigEndian.Uint32(b)) * time.Second
}

// Option is an interface implemented by all Opt* DHCP option types.
type Option interface {
	Type() layers.DHCPOpt
}

// OptSubnetMask represents a SubnetMask DHCP option.
type OptSubnetMask struct {
	Mask net.IPMask
}

// Type implements Option.
func (o *OptSubnetMask) Type() layers.DHCPOpt {
	return layers.DHCPOptSubnetMask
}

// OptBroadcast represents a Broadcast DHCP option.
type OptBroadcast struct {
	Broadcast net.IP
}

// Type implements Option.
func (o *OptBroadcast) Type() layers.DHCPOpt {
	return layers.DHCPOptBroadcastAddr
}

// OptRouter represents a Router DHCP option.
type OptRouter struct {
	Router net.IP
}

// Type implements Option.
func (o *OptRouter) Type() layers.DHCPOpt {
	return layers.DHCPOptRouter
}

// OptDNS represents a DNS DHCP option.
type OptDNS struct {
	DNS []net.IP
}

// Type implements Option.
func (o *OptDNS) Type() layers.DHCPOpt {
	return layers.DHCPOptDNS
}

// OptLeaseTime represents a LeaseTime DHCP option.
type OptLeaseTime struct {
	LeaseTime time.Duration
}

// Type implements Option.
func (o *OptLeaseTime) Type() layers.DHCPOpt {
	return layers.DHCPOptLeaseTime
}

// OptT1 represents a T1 DHCP option.
type OptT1 struct {
	T1 time.Duration
}

// Type implements Option.
func (o *OptT1) Type() layers.DHCPOpt {
	return layers.DHCPOptT1
}

// OptDomainName represents a DomainName DHCP option.
type OptDomainName struct {
	DomainName string
}

// Type implements Option.
func (o *OptDomainName) Type() layers.DHCPOpt {
	return layers.DHCPOptDomainName
}

// ParseOptions converts layers.DHCPOption type/byte-slice pairs into Option.
func ParseOptions(opts []layers.DHCPOption) []Option {
	var results []Option
	for _, o := range opts {
		switch o.Type {
		case layers.DHCPOptSubnetMask:
			results = append(results, &OptSubnetMask{net.IPMask(o.Data)})

		case layers.DHCPOptRouter:
			results = append(results, &OptRouter{net.IP(o.Data)})

		case layers.DHCPOptBroadcastAddr:
			results = append(results, &OptBroadcast{net.IP(o.Data)})

		case layers.DHCPOptDNS:
			var dns []net.IP
			for b := o.Data; len(b) >= 4; b = b[4:] {
				dns = append(dns, net.IP(b[:4]))
			}
			results = append(results, &OptDNS{dns})

		case layers.DHCPOptLeaseTime:
			results = append(results, &OptLeaseTime{parseDHCPDuration(o.Data)})

		case layers.DHCPOptT1:
			results = append(results, &OptT1{parseDHCPDuration(o.Data)})

		case layers.DHCPOptDomainName:
			results = append(results, &OptDomainName{string(o.Data)})
		}
	}
	return results
}

// HasMessageType returns true if any of the specified DHCP options declares the
// DHCP message type to be mt.
func HasMessageType(opts []layers.DHCPOption, mt layers.DHCPMsgType) bool {
	for _, o := range opts {
		if o.Type != layers.DHCPOptMessageType {
			continue
		}
		if len(o.Data) != 1 {
			continue
		}
		if layers.DHCPMsgType(o.Data[0]) == mt {
			return true
		}
	}
	return false
}

// ServerID extracts all ServerID DHCP options. This is convenient when
// responding to a server.
func ServerID(opts []layers.DHCPOption) []layers.DHCPOption {
	for _, o := range opts {
		if o.Type == layers.DHCPOptServerID {
			return []layers.DHCPOption{o}
		}
	}
	return nil
}

// Lease represents a DHCP lease.
type Lease struct {
	IP          net.IP
	Netmask     net.IPMask
	Broadcast   net.IP
	Router      net.IP
	DNS         []net.IP
	Domain      string
	RenewalTime time.Duration
}

// LeaseFromACK constructs a Lease from the specified DHCPACK packet.
func LeaseFromACK(ack *layers.DHCPv4) Lease {
	lease := Lease{
		IP: ack.YourClientIP,
	}
	leaseTime := 10 * time.Minute // seems sensible as a fallback
	// As per RFC 2131 section 4.4.5:
	// renewal time defaults to 50% of the lease time
	var renewalTime *time.Duration
	for _, opt := range ParseOptions(ack.Options) {
		switch o := opt.(type) {
		case *OptSubnetMask:
			lease.Netmask = o.Mask
		case *OptBroadcast:
			lease.Broadcast = o.Broadcast
		case *OptRouter:
			lease.Router = o.Router
		case *OptDomainName:
			lease.Domain = o.DomainName
		case *OptDNS:
			lease.DNS = o.DNS
		case *OptLeaseTime:
			leaseTime = o.LeaseTime
		case *OptT1:
			renewalTime = &o.T1
		}
	}
	if renewalTime == nil {
		d := time.Duration(float64(leaseTime) * 0.5)
		renewalTime = &d
	}
	lease.RenewalTime = *renewalTime
	return lease
}
