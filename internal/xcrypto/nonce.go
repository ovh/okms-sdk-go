// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package xcrypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
)

// NonceSequence is a generator for crypto secure unique nonces.
// It's a prefix + counter based model. Each nonce is the concatenation of the static prefix
// and the nonce sequence number, which is initialized to 0 and sequentially incremented after
// each nonce generation. An additional byte is reserved for marking the last nonce of the sequence.
//
// If the last byte is equal to 0, thent he nonce is not the last one. If it's equal to 1 then the nonce marks the block
// as the last one, and the NonceSequence will fail if trying to advance the sequence.

// The counter is a 32 bites (4 bytes) integer, which allows generation of ~4 million nonces.
type NonceSequence struct {
	prefix   []byte
	nonceLen int
	count    uint32
	// finalized will be set to true if last/final nonce
	// has been used (ie: Marked as being for the last block).
	finalized bool
	// Buffer used to store and generate the next nonce.
	// This buffer is returned as is on each call to Next().
	buf []byte
}

// NewNonceSequence creates a new sequence yielding nonces for size nonceLen.
// If prefix is not null or empty, it must have a size of (nonceLen-5) bytes, and will be used
// as the sequence prefix. Otherwise, a prefix will be generated and can be retrieved using
// the Seed() method.
func NewNonceSequence(nonceLen int, prefix []byte) *NonceSequence {
	if nonceLen <= 5 {
		panic("nonce length must be > 5")
	}
	if len(prefix) == 0 {
		// Generate a random seed
		prefix = make([]byte, nonceLen-5)
		if _, err := rand.Read(prefix); err != nil {
			panic(err)
		}
	} else if len(prefix) != nonceLen-5 {
		panic(fmt.Sprintf("Invalid prefix length (only %d is supported)", nonceLen-5))
	}

	return &NonceSequence{
		prefix:   prefix,
		nonceLen: nonceLen,
		count:    0,
		buf:      nil,
	}
}

// Seed returns the seed used by this sequence.
func (sq *NonceSequence) Seed() []byte {
	return sq.prefix
}

// NonceLength returns the length of the generated nonces.
func (sq *NonceSequence) NonceLength() int {
	return sq.nonceLen
}

// NextInto generate a new nonce and put it in the provided buffer.
// The buffer len must be >= than NonceLength().
// If final is set to true, the nonce will be marked as being the last one,
// and not other nonce can be generated. Subsequent calls to NextInto() will panic.
//
// It also panics if the given buffer nonce does not have a size equals to NonceLength().
func (sq *NonceSequence) NextInto(nonce []byte, final bool) {
	if len(nonce) != sq.nonceLen {
		panic(fmt.Sprintf("Provided buffer must have a size of exactly %d bytes", sq.nonceLen))
	}
	if sq.count == math.MaxUint32 {
		panic("nonce limit reached")
	}
	if sq.finalized {
		panic("nonce sequence has been finalized")
	}

	// The nonce is derived from the prefix and its position in the sequence
	copy(nonce, sq.prefix)
	binary.BigEndian.PutUint32(nonce[len(sq.prefix):], sq.count)
	if final {
		nonce[len(sq.prefix)+4] = 1
		// Make it impossible to generate future nonces
		sq.finalized = true
	}
	sq.count++
}

// Next generates and returns a nonce.
// The returned buffer must not be used after another call to Next().
// If final is set to true, the nonce will be marked as being the last one,
// and not other nonce can be generated. Subsequent calls to Next() will panic.
func (sq *NonceSequence) Next(final bool) []byte {
	if len(sq.buf) < sq.nonceLen {
		sq.buf = make([]byte, sq.nonceLen)
	}

	// Ensure the buffer is not bigger than required
	sq.buf = sq.buf[:sq.nonceLen:sq.nonceLen]
	sq.NextInto(sq.buf, final)
	return sq.buf
}
