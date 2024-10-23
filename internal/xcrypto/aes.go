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
	"crypto/aes"
	"crypto/cipher"
	"io"
)

func newAesGcmAead(key []byte) (cipher.AEAD, error) {
	// Load the key as an AES cipher block
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Load the block into a AES-GCM AEAD cipher
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func NewAesGcmStream(key, seed []byte) (*AEADStream, error) {
	cipher, err := newAesGcmAead(key)
	if err != nil {
		return nil, err
	}
	return NewAEADStream(cipher, seed), nil
}

func NewAesGcmStreamReader(source io.Reader, key, aad, seed []byte, blockSize int) (*AEADStreamReader, error) {
	aead, err := NewAesGcmStream(key, seed)
	if err != nil {
		return nil, err
	}
	return NewAEADStreamReader(aead, source, aad, blockSize)
}

func NewAesGcmStreamWriter(dst io.Writer, key, aad, seed []byte, blockSize int) (*AEADStreamWriter, error) {
	aead, err := NewAesGcmStream(key, seed)
	if err != nil {
		return nil, err
	}
	return NewAEADStreamWriter(aead, dst, aad, blockSize)
}
