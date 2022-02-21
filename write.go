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
	"github.com/mdlayher/packet"
	"github.com/mdlayher/raw"
)

var ip, udp = func() (*layers.IPv4, *layers.UDP) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("0.0.0.0"),
		DstIP:    net.ParseIP("255.255.255.255"),
	}
	udp := &layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	udp.SetNetworkLayerForChecksum(ip)
	return ip, udp
}()

// Write encodes pkt as an IPv4 packet to pc.
func Write(pc net.PacketConn, pkt *layers.DHCPv4) error {
	buf := gopacket.NewSerializeBuffer()
	// TODO: padding: add 0 bytes until at least 272 bytes
	// probably in gopacket itself, see also https://github.com/google/gopacket/issues/361
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		ip,
		udp,
		pkt,
	)

	// Temporary shim for mdlayher/raw to mdlayher/packet transition.
	var broadcast net.Addr
	switch pc.(type) {
	case *packet.Conn:
		broadcast = &packet.Addr{HardwareAddr: layers.EthernetBroadcast}
	case *raw.Conn:
		broadcast = &raw.Addr{HardwareAddr: layers.EthernetBroadcast}
	}

	_, err := pc.WriteTo(buf.Bytes(), broadcast)
	return err
}
