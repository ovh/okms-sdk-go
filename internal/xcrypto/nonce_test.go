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
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func hexbyte(in string) []byte {
	b, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	seed = hexbyte("479247a088ab29")

	nonces = [][]byte{
		hexbyte("479247a088ab290000000000"),
		hexbyte("479247a088ab290000000100"),
		hexbyte("479247a088ab290000000200"),
		hexbyte("479247a088ab290000000300"),
		hexbyte("479247a088ab290000000400"),
		hexbyte("479247a088ab290000000500"),
		hexbyte("479247a088ab290000000600"),
		hexbyte("479247a088ab290000000700"),
		hexbyte("479247a088ab290000000800"),
		hexbyte("479247a088ab290000000900"),
	}

	nonceLen = len(seed) + 5
)

func TestNonceSequencer(t *testing.T) {
	seq := NewNonceSequence(nonceLen, seed)
	for _, nonce := range nonces {
		assert.Equal(t, nonce, seq.Next(false))
	}
	assert.Equal(t, nonceLen, seq.NonceLength())

	seq = NewNonceSequence(nonceLen, hexbyte("479247a088ab28"))
	for _, nonce := range nonces {
		assert.NotEqual(t, nonce, seq.Next(false))
	}

	seq1 := NewNonceSequence(nonceLen, nil)
	seq2 := NewNonceSequence(nonceLen, nil)

	assert.NotEmpty(t, seq1.Seed())
	assert.NotEmpty(t, seq2.Seed())

	for i := 0; i < 1000; i++ {
		assert.NotEqual(t, seq1.Next(false), seq2.Next(false))
	}

	seq = NewNonceSequence(42, nil)
	assert.Equal(t, 42, seq.NonceLength())
	for i := 0; i < 1000; i++ {
		assert.Len(t, seq.Next(false), 42)
	}

	assert.Panics(t, func() { NewNonceSequence(nonceLen, hexbyte("1234567890abcdef1234567890abcdef")) })
	assert.Panics(t, func() { NewNonceSequence(0, nil) })
	assert.Panics(t, func() { NewNonceSequence(-1, nil) })

	seq = NewNonceSequence(nonceLen, seed)
	bytes := make([]byte, seq.NonceLength())
	seq.NextInto(bytes, false)
	assert.Equal(t, nonces[0], bytes)

	assert.Panics(t, func() { seq.NextInto(nil, false) })
	assert.Panics(t, func() { seq.NextInto([]byte{1, 2, 3}, false) })
}

func TestNonceFinalize(t *testing.T) {
	seq := NewNonceSequence(nonceLen, seed)
	assert.Equal(t, nonces[0], seq.Next(false))

	nonce := nonces[1]
	nonce[len(nonce)-1] = 1
	assert.Equal(t, nonce, seq.Next(true))

	assert.Panics(t, func() { seq.Next(false) })
	assert.Panics(t, func() { seq.Next(true) })
}

func TestNonceMaximum(t *testing.T) {
	seq := NewNonceSequence(nonceLen, seed)
	seq.count = math.MaxUint32 - 1 // Force the count to be almost at the end
	seq.Next(false)
	assert.Panics(t, func() { seq.Next(false) })
}
