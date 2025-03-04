// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package okms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"math"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/internal/utils"
	"github.com/ovh/okms-sdk-go/internal/xcrypto"
)

// DataKeys creates a new datakey provider for the given service key.
func (client *Client) DataKeys(serviceKeyID uuid.UUID) *DataKeyProvider {
	return newDataKeyProvider(client, serviceKeyID)
}

// DataKeyProvider is a helper provider that wraps an API client
// and provides helpers functions to repeatedly generate or decrypt datakeys
// protected by the same service key.
//
// It also provide helper functions to directly encrypt or decrypt data with a datakey.
type DataKeyProvider struct {
	api   DataKeyApi
	keyId uuid.UUID
}

// newDataKeyProvider creates a new datakey provider for the given service key,
// using the given [DataKeyApi] api client.
func newDataKeyProvider(api DataKeyApi, keyId uuid.UUID) *DataKeyProvider {
	return &DataKeyProvider{
		api:   api,
		keyId: keyId,
	}
}

// GenerateDataKey creates a new datakey of bitlen `size` and with name `name`,
// protected by the provider's service key. The `plain` and `encrypted` form of the datakey are returned.
//
// Acceptable key sizes are 128, 192 and 256.
// The encrypted key can later be decrypted by calling [DataKeyProvider.DecryptDataKey].
func (sk *DataKeyProvider) GenerateDataKey(ctx context.Context, name string, size int) (plain, encrypted []byte, err error) {
	if size < 0 || size > math.MaxInt32 {
		return nil, nil, errors.New("key size is out of bound")
	}
	// Let's first ask the KMS to generate a new DK
	plain, encryptedKey, err := sk.api.GenerateDataKey(ctx, sk.keyId, name, utils.ToInt32(size))
	if err != nil {
		return nil, nil, err
	}

	return plain, []byte(encryptedKey), nil
}

// DecryptDataKey decrypts an encrypted datakey like ones returned by [DataKeyProvider.GenerateDataKey].
func (sk *DataKeyProvider) DecryptDataKey(ctx context.Context, key []byte) ([]byte, error) {
	// Call KMS to decrypt the key
	keyPlain, err := sk.api.DecryptDataKey(ctx, sk.keyId, string(key))
	if err != nil {
		return nil, err
	}
	return keyPlain, nil
}

// EncryptGCM is a helper function that creates a new 256 bits datakey, and encrypts the given data
// with AES-GCM.
//
// On success, the function returns the encrypted data, the encrypted key, and the random nonce used.
// Those 3 values must later be passed to [DataKeyProvider.DecryptGCM] in order to decrypt the data.
func (sk *DataKeyProvider) EncryptGCM(ctx context.Context, keyName string, data, aad []byte) (cipherText, cipherKey, nonce []byte, err error) {
	slog.Debug("Generating new data key", "keyId", sk.keyId)
	plainKey, encryptedKey, err := sk.GenerateDataKey(ctx, keyName, 256)
	if err != nil {
		return nil, nil, nil, err
	}

	aesCipher, err := aes.NewCipher(plainKey)
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, nil, nil, err
	}

	slog.Debug("Generating a random nonce", "size", aead.NonceSize())
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}

	slog.Debug("Encrypting data", "size", len(data))
	cipherText = aead.Seal(cipherText, nonce, data, aad)
	return cipherText, encryptedKey, nonce, nil
}

// DecryptGCM is a helper function that decrypts the given encrypted datakey, than decrypts the given cipherText using the reulting plain key
// with the given nonce and aad, using AES-GCM.
//
// It's mostly used to decrypt data encrypted using [DataKeyProvider.EncryptGCM].
func (sk *DataKeyProvider) DecryptGCM(ctx context.Context, cipherKey, cipherText, nonce, aad []byte) ([]byte, error) {
	slog.Debug("Decrypting data key", "keyId", sk.keyId)
	plainKey, err := sk.DecryptDataKey(ctx, cipherKey)
	if err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(plainKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}
	slog.Debug("Decrypting data", "size", len(cipherText))
	data, err := aead.Open(nil, nonce, cipherText, aad)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// BlockSize enumerates recommended size of blocks for streaming encryption.
type BlockSize int

const (
	BlockSize32kB    BlockSize = 32 * 1024
	BlockSize4MB     BlockSize = 4096 * 1024
	BlockSizeDefault BlockSize = xcrypto.DEFAULT_BLOCK_SIZE
)

// EncryptStream wraps the given io.Writer into an io.WriteCloser that encrypts the data written to it with a fresh new datakey.
// A 256 bits datakey is generated for every new stream, is used to perform an AES-GCM encryption of successive blocks of data.
// The encrypted stream will start with a header containing the encrypted datakey and a random initialization vector.
//
// The returned io.WriteCloser must be closed to finalize the encryption, but please note that doing so won't close the underlying stream
// which must also be closed but can be reused first.
func (sk *DataKeyProvider) EncryptStream(ctx context.Context, w io.Writer, aad []byte, blockSize BlockSize) (io.WriteCloser, error) {
	return xcrypto.NewDatakeyAEADStream(sk).SealTo(ctx, w, aad, int(blockSize))
}

// DecryptStream wraps the given io.Reader into another io.Reader that decrypts the data read from it. The initialization vector
// and the encrypted datakey are read from the header. The datakey is then decrypted on KMS and used to decrypt successive blocks of encrypted data
// using AES-GCM.
//
// The data to decrypt must have been encrypted using DataKeyProvider.EncryptStream.
func (sk *DataKeyProvider) DecryptStream(ctx context.Context, r io.Reader, aad []byte) (io.Reader, error) {
	return xcrypto.NewDatakeyAEADStream(sk).OpenFrom(ctx, r, aad)
}
