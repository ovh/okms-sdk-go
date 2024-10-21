// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package utils

import "math"

// Integer regroups all types that are either an interger,
// or an alias over an integer type.
type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// ToUint32 safely casts the given integer to uint32
// by checking bounds and panicking if overflow occures.
// It's used to avoid unexpected issues when casting integers.
func ToUint32[N Integer](n N) uint32 {
	if n < 0 || uint64(n) > math.MaxUint32 {
		panic("Integer overflow")
	}
	return uint32(n)
}

// ToUint16 safely casts the given integer to uint16
// by checking bounds and panicking if overflow occures.
// It's used to avoid unexpected issues when casting integers.
func ToUint16[N Integer](n N) uint16 {
	if n < 0 || uint64(n) > math.MaxUint16 {
		panic("Integer overflow")
	}
	return uint16(n)
}
