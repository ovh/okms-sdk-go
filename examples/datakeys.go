// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
)

func dataKeyEncryptDecrypt(ctx context.Context, kmsClient okms.Client) {
	// Create a new AES 256 key
	respAes, err := kmsClient.CreateImportServiceKey(ctx, nil, types.CreateImportServiceKeyRequest{
		Name:       "AES key example",
		Type:       ptrTo(types.Oct),
		Size:       ptrTo(types.N256),
		Operations: ptrTo([]types.CryptographicUsages{types.Encrypt, types.Decrypt, types.WrapKey, types.UnwrapKey}),
	})
	if err != nil {
		panic(err)
	}

	data := "Hello World !!!" // Data to encrypt

	dkProvider := okms.NewDataKeyProvider(kmsClient, respAes.Id)

	// ENCRYPTION

	// Generate a new datakey
	plain, encrypted, err := dkProvider.GenerateDataKey(ctx, "Example DK", 256)
	if err != nil {
		panic(err)
	}

	// Initialize AES GCM cipher with the plain key
	aesCipher, err := aes.NewCipher(plain)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// Encrypt the data
	encryptedData := gcm.Seal(nil, nonce, []byte(data), []byte("Some additional data"))

	// Now forget about the plain data key
	clear(plain)

	// DECRYPTION

	// Decrypt data key
	plain, err = dkProvider.DecryptDataKey(ctx, encrypted)
	if err != nil {
		panic(err)
	}
	// Initialize AES GCM cipher with the decrypted key
	aesCipher, err = aes.NewCipher(plain)
	if err != nil {
		panic(err)
	}
	gcm, err = cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}

	// Decrypt text
	plainData, err := gcm.Open(nil, nonce, encryptedData, []byte("Some additional data"))
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", string(plainData))

	// ALTERNATIVE

	// Unless you want to use another algorithm than AES-GCM 256 bits, you can use the 2 following helper methods:
	encryptedData, encryptedKey, nonce, err := dkProvider.EncryptGCM(ctx, "Example DK", []byte(data), []byte("Some additional data"))
	if err != nil {
		panic(err)
	}

	plainData, err = dkProvider.DecryptGCM(ctx, encryptedKey, encryptedData, nonce, []byte("Some additional data"))
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", string(plainData))
}

func dataKeyEncryptStream(ctx context.Context, kmsClient okms.Client) {
	// Create a new AES 256 key
	respAes, err := kmsClient.CreateImportServiceKey(ctx, nil, types.CreateImportServiceKeyRequest{
		Name:       "AES key example",
		Type:       ptrTo(types.Oct),
		Size:       ptrTo(types.N256),
		Operations: ptrTo([]types.CryptographicUsages{types.Encrypt, types.Decrypt, types.WrapKey, types.UnwrapKey}),
	})
	if err != nil {
		panic(err)
	}

	dkProvider := okms.NewDataKeyProvider(kmsClient, respAes.Id)

	sourceFile, err := os.Open("10GB_Plain_File.txt")
	if err != nil {
		panic(err)
	}
	defer sourceFile.Close()
	targetFile, err := os.Create("Encrypted_File.bin")
	if err != nil {
		panic(err)
	}
	defer targetFile.Close()

	stream, err := dkProvider.EncryptStream(context.Background(), targetFile, []byte("Optional Additional Authenticated Data"), okms.BlockSize4MB)
	if err != nil {
		panic(err)
	}
	// Encryption stream must be closed to ensure the last encrypted block is written
	defer stream.Close()

	_, err = io.Copy(stream, bufio.NewReader(sourceFile))
	if err != nil {
		panic(err)
	}
}

func dataKeyDecryptStream(ctx context.Context, kmsClient okms.Client) {
	// Create a new AES 256 key
	respAes, err := kmsClient.CreateImportServiceKey(ctx, nil, types.CreateImportServiceKeyRequest{
		Name:       "AES key example",
		Type:       ptrTo(types.Oct),
		Size:       ptrTo(types.N256),
		Operations: ptrTo([]types.CryptographicUsages{types.Encrypt, types.Decrypt, types.WrapKey, types.UnwrapKey}),
	})
	if err != nil {
		panic(err)
	}

	dkProvider := okms.NewDataKeyProvider(kmsClient, respAes.Id)

	sourceFile, err := os.Create("Encrypted_File.bin")
	if err != nil {
		panic(err)
	}
	defer sourceFile.Close()
	targetFile, err := os.Open("10GB_Plain_File.txt")
	if err != nil {
		panic(err)
	}
	defer targetFile.Close()

	stream, err := dkProvider.DecryptStream(context.Background(), sourceFile, []byte("Optional Additional Authenticated Data"))
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(targetFile, stream)
	if err != nil {
		panic(err)
	}
}
