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
	"hash/fnv"
	"math/rand"
	"net"
	"sync"
	"time"
)

// XIDGenerator returns a function which returns DHCP transaction IDs (xid).
func XIDGenerator(hwaddr net.HardwareAddr) func() uint32 {
	// https://tools.ietf.org/html/rfc2131#section-4.1 explains:
	//
	// A DHCP client MUST choose 'xid's in such a way as to minimize the chance
	// of using an 'xid' identical to one used by another client.
	//
	// Hence, seed a random number generator with the current time and hardware
	// address.
	h := fnv.New64()
	h.Write(hwaddr)
	seed := int64(h.Sum64()) + time.Now().Unix()
	rnd := rand.New(rand.NewSource(seed))
	var rndMu sync.Mutex
	buf := make([]byte, 4)
	return func() uint32 {
		rndMu.Lock()
		defer rndMu.Unlock()
		rnd.Read(buf)
		return binary.BigEndian.Uint32(buf)
	}
}
