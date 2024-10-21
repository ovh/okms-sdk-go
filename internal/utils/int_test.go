// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package utils

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToUint32(t *testing.T) {
	assert.Equal(t, uint32(12), ToUint32(int8(12)))
	assert.Equal(t, uint32(12), ToUint32(uint8(12)))
	assert.Equal(t, uint32(12), ToUint32(int64(12)))
	assert.Equal(t, uint32(12), ToUint32(uint64(12)))
	assert.Equal(t, uint32(0), ToUint32(int64(0)))
	assert.Equal(t, uint32(0), ToUint32(uint64(0)))

	assert.Panics(t, func() {
		ToUint32(uint64(math.MaxUint32 + 1))
	})

	assert.Panics(t, func() {
		ToUint32(int8(-12))
	})
}

func TestToUint16(t *testing.T) {
	assert.Equal(t, uint16(12), ToUint16(int8(12)))
	assert.Equal(t, uint16(12), ToUint16(uint8(12)))
	assert.Equal(t, uint16(12), ToUint16(int64(12)))
	assert.Equal(t, uint16(12), ToUint16(uint64(12)))
	assert.Equal(t, uint16(0), ToUint16(int64(0)))
	assert.Equal(t, uint16(0), ToUint16(uint64(0)))

	assert.Panics(t, func() {
		ToUint16(uint64(math.MaxUint16 + 1))
	})

	assert.Panics(t, func() {
		ToUint16(int8(-12))
	})
}
