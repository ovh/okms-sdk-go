// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package okms_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
)

func ExampleNewRestAPIClientWithHttp() {
	cert, err := tls.LoadX509KeyPair(os.Getenv("OKMS_CLIENT_CERT_FILE"), os.Getenv("OKMS_CLIENT_KEY_FILE"))
	if err != nil {
		panic(err)
	}
	httpClient := http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}},
	}

	okmsIdString := os.Getenv("OKMS_ID")
	okmsId, err := uuid.Parse(okmsIdString)
	if err != nil {
		panic(err)
	}

	kmsClient, err := okms.NewRestAPIClientWithHttp("https://eu-west-rbx.okms.ovh.net", &httpClient)
	if err != nil {
		panic(err)
	}

	// Use KMS client, for example to activate a service key
	if err := kmsClient.ActivateServiceKey(context.Background(), okmsId, uuid.MustParse("2dab95dc-d7d3-482b-a07b-6b4dfae89d58")); err != nil {
		panic(err)
	}
}

// Generate an 256 bits AES key
func ExampleClient_CreateImportServiceKey_generateAES() {
	var kmsClient *okms.Client // Initialize client
	kType := types.Oct
	kSize := types.N256
	ops := []types.CryptographicUsages{types.Encrypt, types.Decrypt, types.WrapKey, types.UnwrapKey}
	// Create a new AES 256 key
	respAes, err := kmsClient.CreateImportServiceKey(context.Background(), uuid.MustParse("7745c93b-8ed3-4eef-921c-87bd8bbdd01b"), nil, types.CreateImportServiceKeyRequest{
		Name:       "AES key example",
		Type:       &kType,
		Size:       &kSize,
		Operations: &ops,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("AES KEY:", respAes.Id)
}

// Generate a 2048 bits RSA key pair
func ExampleClient_CreateImportServiceKey_generateRSA() {
	var kmsClient *okms.Client // Initialize client
	kType := types.RSA
	kSize := types.N2048
	ops := []types.CryptographicUsages{types.Sign, types.Verify}
	// Create a new RSA 2048 key-pair
	respRSA, err := kmsClient.CreateImportServiceKey(context.Background(), uuid.MustParse("7745c93b-8ed3-4eef-921c-87bd8bbdd01b"), nil, types.CreateImportServiceKeyRequest{
		Name:       "RSA key-pair example",
		Type:       &kType,
		Size:       &kSize,
		Operations: &ops,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("RSA KEY:", respRSA.Id)
}

// Generate an ECDSA key pair on the P-256 curve
func ExampleClient_CreateImportServiceKey_generateECDSA() {
	var kmsClient *okms.Client // Initialize client
	kType := types.EC
	curve := types.P256
	ops := []types.CryptographicUsages{types.Sign, types.Verify}
	// Create a new ECDSA P-256 key-pair
	respEC, err := kmsClient.CreateImportServiceKey(context.Background(), uuid.MustParse("7745c93b-8ed3-4eef-921c-87bd8bbdd01b"), nil, types.CreateImportServiceKeyRequest{
		Name:       "ECDSA key-pair example",
		Type:       &kType,
		Curve:      &curve,
		Operations: &ops,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("ECDSA KEY:", respEC.Id)
}

func ExampleClient_Sign() {
	var kmsClient *okms.Client // Initialize client
	data := "Hello World !!!"  // Data to sign
	format := types.Raw
	signResponse, err := kmsClient.Sign(
		context.Background(),
		uuid.MustParse("7745c93b-8ed3-4eef-921c-87bd8bbdd01b"),
		uuid.MustParse("2dab95dc-d7d3-482b-a07b-6b4dfae89d58"),
		&format,
		types.ES256,
		false,
		[]byte(data),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signature:", signResponse)
}

func ExampleClient_Verify() {
	var kmsClient *okms.Client // Initialize client
	var signature string       // Base64 encoded signature
	data := "Hello World !!!"  // Data to sign
	result, err := kmsClient.Verify(
		context.Background(),
		uuid.MustParse("7745c93b-8ed3-4eef-921c-87bd8bbdd01b"),
		uuid.MustParse("2dab95dc-d7d3-482b-a07b-6b4dfae89d58"),
		types.ES256,
		false,
		[]byte(data),
		signature,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Is valid:", result)
}

func ExampleDataKeyProvider_helpers() {
	var kmsClient *okms.Client // Initialize client

	data := "Hello World !!!" // Data to encrypt
	dkProvider := kmsClient.DataKeys(uuid.MustParse("7745c93b-8ed3-4eef-921c-87bd8bbdd01b"), uuid.MustParse("2dab95dc-d7d3-482b-a07b-6b4dfae89d58"))

	// Unless you want to use another algorithm than AES-GCM 256 bits, you can use the 2 following helper methods:
	encryptedData, encryptedKey, nonce, err := dkProvider.EncryptGCM(context.Background(), "Example DK", []byte(data), []byte("Some additional data"))
	if err != nil {
		panic(err)
	}

	plainData, err := dkProvider.DecryptGCM(context.Background(), encryptedKey, encryptedData, nonce, []byte("Some additional data"))
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", string(plainData))
}

func ExampleDataKeyProvider_GenerateDataKey() {
	var kmsClient *okms.Client // Initialize client
	data := "Hello World !!!"  // Data to encrypt
	dkProvider := kmsClient.DataKeys(uuid.MustParse("7745c93b-8ed3-4eef-921c-87bd8bbdd01b"), uuid.MustParse("2dab95dc-d7d3-482b-a07b-6b4dfae89d58"))

	// Generate a new datakey
	plain, encrypted, err := dkProvider.GenerateDataKey(context.Background(), "Example DK", 256)
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

	fmt.Println("EncryptedKey:", encrypted, ", Encrypted data:", base64.StdEncoding.EncodeToString(encryptedData))
}

func ExampleDataKeyProvider_DecryptDataKey() {
	var kmsClient *okms.Client // Initialize client
	var encryptedData []byte   // Some encrypted data
	var encryptedKey []byte    // Encrypted datakey
	var nonce []byte           // Nonce used for data encryption
	dkProvider := kmsClient.DataKeys(uuid.MustParse("7745c93b-8ed3-4eef-921c-87bd8bbdd01b"), uuid.MustParse("2dab95dc-d7d3-482b-a07b-6b4dfae89d58"))

	// Decrypt data key
	plain, err := dkProvider.DecryptDataKey(context.Background(), encryptedKey)
	if err != nil {
		panic(err)
	}
	// Initialize AES GCM cipher with the decrypted key
	aesCipher, err := aes.NewCipher(plain)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}

	// Decrypt text
	plainData, err := gcm.Open(nil, nonce, encryptedData, []byte("Some additional data"))
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", string(plainData))
}
