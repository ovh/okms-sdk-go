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

func encryptDecrypt(ctx context.Context, kmsClient *okms.Client) {
	// Create a new AES 256 key
	respAes, err := kmsClient.GenerateSymmetricKey(ctx, types.N256, "AES key example", "", types.Encrypt, types.Decrypt)
	if err != nil {
		panic(err)
	}

	// Encrypt some data
	encryptResp, err := kmsClient.Encrypt(ctx, respAes.Id, "", []byte("My super secret message."))
	if err != nil {
		panic(err)
	}
	fmt.Println("Encrypted message:", encryptResp)

	// And later decrypt those data
	decryptResp, err := kmsClient.Decrypt(ctx, respAes.Id, "", encryptResp)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted message:", string(decryptResp))
}
