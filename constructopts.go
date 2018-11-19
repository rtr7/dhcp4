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

	"github.com/google/gopacket/layers"
)

// MessageTypeOpt is a short-hand for constructing a MessageType DHCP option.
func MessageTypeOpt(msgType layers.DHCPMsgType) layers.DHCPOption {
	return layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)})
}

// HostnameOpt is a short-hand for constructing a Hostname DHCP option.
func HostnameOpt(hostname string) layers.DHCPOption {
	// TODO: limit length
	return layers.NewDHCPOption(layers.DHCPOptHostname, []byte(hostname))
}

// ClientIDOpt is a short-hand for constructing a ClientID DHCP option.
func ClientIDOpt(linkType layers.LinkType, hwaddr net.HardwareAddr) layers.DHCPOption {
	return layers.NewDHCPOption(layers.DHCPOptClientID, append([]byte{byte(linkType)}, hwaddr...))
}

// ParamsRequestOpt is a short-hand for constructing a ParamsRequest DHCP option.
func ParamsRequestOpt(opts ...layers.DHCPOpt) layers.DHCPOption {
	b := make([]byte, len(opts))
	for idx, opt := range opts {
		b[idx] = byte(opt)
	}
	return layers.NewDHCPOption(layers.DHCPOptParamsRequest, b)
}

// RequestIPOpt is a short-hand for constructing a RequestIP DHCP option.
func RequestIPOpt(requestIP net.IP) layers.DHCPOption {
	return layers.NewDHCPOption(layers.DHCPOptRequestIP, []byte(requestIP))
}
