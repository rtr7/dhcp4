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
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	minIPHdrLen = 20
	maxIPHdrLen = 60
	udpHdrLen   = 8
	ip4Ver      = 0x40
	ttl         = 16
	srcPort     = 68
	dstPort     = 67
	maxDHCPLen  = 576
)

// Read decodes an IPv4 packet from pc, returning its DHCPv4 layer or nil.
func Read(pc net.PacketConn) (*layers.DHCPv4, error) {
	buf := make([]byte, maxIPHdrLen+udpHdrLen+maxDHCPLen)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	pkt := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.DecodeOptions{})
	dhcp := pkt.Layer(layers.LayerTypeDHCPv4)
	if dhcp == nil {
		return nil, nil
	}
	return dhcp.(*layers.DHCPv4), nil
}
