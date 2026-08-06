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
	"fmt"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
)

func listKeys(ctx context.Context, okmsClient *okms.Client, okmsId uuid.UUID) {
	it := okmsClient.ListAllServiceKeys(okmsId, nil, nil)
	for it.Next(ctx) {
		key, err := it.Value()
		if err != nil {
			panic(err)
		}
		fmt.Println(key)
	}

	// You can also range over go 1.23+ iterator:
	for key, err := range okmsClient.ListAllServiceKeys(okmsId, nil, nil).Iter(ctx) {
		if err != nil {
			panic(err)
		}
		fmt.Println(key.Id)
	}
}

func getKey(ctx context.Context, okmsClient *okms.Client, okmsId uuid.UUID) {
	// Create a new AES 256 key
	respAes, err := okmsClient.GenerateSymmetricKey(ctx, okmsId, types.N256, "AES key example", types.SOFTWARE, "", []types.CryptographicUsages{types.Encrypt, types.Decrypt, types.WrapKey, types.UnwrapKey})
	if err != nil {
		panic(err)
	}

	getResp, err := okmsClient.GetServiceKey(ctx, okmsId, respAes.Id, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Key:", getResp.Id)
}

// getWrappedKey exports the key material of a service key in wrapped (encrypted) form.
func getWrappedKey(ctx context.Context, okmsClient *okms.Client, okmsId uuid.UUID) {
	// Generate the transport key used to wrap the exported material. It must be a RSA key-pair with the wrapKey usage.
	transportKey, err := okmsClient.GenerateRSAKeyPair(ctx, okmsId, types.N4096, "Transport key example", types.SOFTWARE, "", []types.CryptographicUsages{types.WrapKey})
	if err != nil {
		panic(err)
	}

	// The key to export. It must be extractable for its key material to be exportable.
	aesKey, err := okmsClient.GenerateSymmetricKey(ctx, okmsId, types.N256, "AES key to export", types.SOFTWARE, "", []types.CryptographicUsages{types.Encrypt, types.Decrypt}, okms.WithExtractable(true))
	if err != nil {
		panic(err)
	}

	// The KMS encrypts the key material with the transport key, and returns it as a JWE Compact Serialization string.
	wrappedKeys, err := okmsClient.GetWrappedServiceKey(ctx, okmsId, aesKey.Id, transportKey.Id, types.RAW, types.RSAOAEP256)
	if err != nil {
		panic(err)
	}

	for _, wrapped := range wrappedKeys {
		fmt.Println("WRAPPED KEY:", wrapped.KeyFormatType, wrapped.WrappingKeyId, wrapped.Ciphertext)
	}
}
