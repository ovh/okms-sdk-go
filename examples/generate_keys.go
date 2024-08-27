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

	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
)

func generateKeys(ctx context.Context, kmsClient okms.Client) {
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
	fmt.Println("AES KEY:", respAes.Id)

	// Create a new RSA 2048 key-pair
	respRSA, err := kmsClient.CreateImportServiceKey(ctx, nil, types.CreateImportServiceKeyRequest{
		Name:       "RSA key-pair example",
		Type:       ptrTo(types.RSA),
		Size:       ptrTo(types.N2048),
		Operations: ptrTo([]types.CryptographicUsages{types.Sign, types.Verify}),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("RSA KEY:", respRSA.Id)

	// Create a new ECDSA P-256 key-pair
	respECDSA, err := kmsClient.CreateImportServiceKey(ctx, nil, types.CreateImportServiceKeyRequest{
		Name:       "ECDSA key-pair example",
		Type:       ptrTo(types.EC),
		Curve:      ptrTo(types.P256),
		Operations: ptrTo([]types.CryptographicUsages{types.Sign, types.Verify}),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("ECDSA KEY:", respECDSA.Id)
}
