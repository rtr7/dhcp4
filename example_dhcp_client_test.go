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

package dhcp4_test

import (
	"log"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/mdlayher/packet"
	"github.com/rtr7/dhcp4"
)

func Example() {
	iface, err := net.InterfaceByName("uplink0")
	if err != nil {
		log.Fatal(err)
	}
	xidGen := dhcp4.XIDGenerator(iface.HardwareAddr)
	conn, err := packet.Listen(iface, packet.Datagram, syscall.ETH_P_IP, nil)
	if err != nil {
		log.Fatal(err)
	}
	discover := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  uint8(len(layers.EthernetBroadcast)),
		Xid:          xidGen(),
		ClientHWAddr: iface.HardwareAddr,
		Options: []layers.DHCPOption{
			dhcp4.MessageTypeOpt(layers.DHCPMsgTypeDiscover),
			dhcp4.HostnameOpt("dhcpprobe"),
			dhcp4.ClientIDOpt(layers.LinkTypeEthernet, iface.HardwareAddr),
		},
	}
	if err := dhcp4.Write(conn, discover); err != nil {
		log.Fatal(err)
	}

	// Display all DHCPOFFER packets received within 5s:
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		offer, err := dhcp4.Read(conn)
		if err != nil {
			log.Fatal(err)
		}
		if offer == nil {
			continue // not a DHCPv4 packet
		}
		if offer.Xid != discover.Xid {
			continue // broadcast reply for different DHCP transaction
		}
		if !dhcp4.HasMessageType(offer.Options, layers.DHCPMsgTypeOffer) {
			continue
		}
		log.Printf("DHCPOFFER: %+v", offer)
	}
}
