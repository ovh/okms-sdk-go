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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
)

// importPlainKeys imports locally generated key material into the KMS, in plain form.
func importPlainKeys(ctx context.Context, okmsClient *okms.Client, okmsId uuid.UUID) {
	// Import a locally generated RSA 2048 key-pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	respRSA, err := okmsClient.ImportKey(ctx, okmsId, rsaKey, "Imported RSA key-pair", "", []types.CryptographicUsages{types.Sign, types.Verify})
	if err != nil {
		panic(err)
	}
	fmt.Println("IMPORTED RSA KEY:", respRSA.Id)

	// Import only the public part of an ECDSA key-pair
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	respECPub, err := okmsClient.ImportKey(ctx, okmsId, &ecKey.PublicKey, "Imported ECDSA public key", "", []types.CryptographicUsages{types.Verify})
	if err != nil {
		panic(err)
	}
	fmt.Println("IMPORTED ECDSA PUBLIC KEY:", respECPub.Id)

	// Key material can also be imported directly from its PEM encoding
	ecDer, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		panic(err)
	}
	ecPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDer})
	respECDSA, err := okmsClient.ImportKeyPairPEM(ctx, okmsId, ecPem, "Imported ECDSA key-pair", "", []types.CryptographicUsages{types.Sign, types.Verify}, okms.WithKeyID(uuid.New()))
	if err != nil {
		panic(err)
	}
	fmt.Println("IMPORTED ECDSA KEY:", respECDSA.Id)
}

// importWrappedKeys imports key material that has been wrapped (encrypted) with the
// public part of a transport key held by the KMS.
//
// The wrapped material used here is produced by the KMS itself, with a wrapped export of an
// existing key. In a real bring-your-own-key scenario it is produced outside of the KMS, by
// encrypting the key material with the public part of the transport key.
func importWrappedKeys(ctx context.Context, okmsClient *okms.Client, okmsId uuid.UUID) {
	// Create the transport key. It must be a RSA key-pair with the unwrapKey usage,
	// and the wrapKey usage if it is also to be used for wrapped exports.
	transportKey, err := okmsClient.GenerateRSAKeyPair(ctx, okmsId, types.N4096, "Transport key example", types.SOFTWARE, "", []types.CryptographicUsages{types.WrapKey, types.UnwrapKey})
	if err != nil {
		panic(err)
	}
	fmt.Println("TRANSPORT KEY:", transportKey.Id)

	// Create the keys to be exported and then re-imported. They must be extractable for their key material to be exportable.
	srcAes, err := okmsClient.GenerateSymmetricKey(ctx, okmsId, types.N256, "AES key to re-import", types.SOFTWARE, "", []types.CryptographicUsages{types.Encrypt, types.Decrypt}, okms.WithExtractable(true))
	if err != nil {
		panic(err)
	}
	srcRSA, err := okmsClient.GenerateRSAKeyPair(ctx, okmsId, types.N2048, "RSA key-pair to re-import", types.SOFTWARE, "", []types.CryptographicUsages{types.Sign, types.Verify}, okms.WithExtractable(true))
	if err != nil {
		panic(err)
	}

	// Import a wrapped symmetric key in RAW format.
	aesID := reimportWrappedKey(ctx, okmsClient, okmsId, srcAes.Id, transportKey.Id, types.RAW, "Imported wrapped AES key", []types.CryptographicUsages{types.Encrypt, types.Decrypt})
	fmt.Println("IMPORTED WRAPPED AES KEY:", aesID)

	// Import a wrapped key-pair in PKCS8 format.
	rsaID := reimportWrappedKey(ctx, okmsClient, okmsId, srcRSA.Id, transportKey.Id, types.PKCS8, "Imported wrapped RSA key-pair", []types.CryptographicUsages{types.Sign, types.Verify})
	fmt.Println("IMPORTED WRAPPED RSA KEY:", rsaID)
}

// reimportWrappedKey exports the material of the key `keyId` wrapped with the transport key
// `transportKeyId`, then imports it back into the KMS as a new key, and returns its ID.
func reimportWrappedKey(ctx context.Context, okmsClient *okms.Client, okmsId, keyId, transportKeyId uuid.UUID, keyFormat types.KeyFormatTypes, name string, ops []types.CryptographicUsages) uuid.UUID {
	// The KMS encrypts the key material with the transport key, and returns it as a JWE Compact Serialization string.
	wrappedKeys, err := okmsClient.GetWrappedServiceKey(ctx, okmsId, keyId, transportKeyId, keyFormat, types.RSAOAEP256)
	if err != nil {
		panic(err)
	}

	wrapped := wrappedKeys[0]

	// The KMS unwraps the material with the transport key, and infers the key type, size and
	// curve from it. Add okms.WithExtractable(false) to make the imported key non-exportable.
	resp, err := okmsClient.ImportWrappedServiceKey(ctx, okmsId, wrapped.WrappingKeyId, wrapped.Ciphertext, wrapped.KeyFormatType, name, "", ops)
	if err != nil {
		panic(err)
	}
	return resp.Id
}
