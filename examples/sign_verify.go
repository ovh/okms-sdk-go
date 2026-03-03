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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
)

func signVerify(ctx context.Context, kmsClient *okms.Client, okmsId uuid.UUID) {
	// Create a new ECDSA P-256 key-pair. Sign / Verify also works with RSA keys
	respECDSA, err := kmsClient.GenerateECKeyPair(ctx, okmsId, types.P256, "ECDSA key-pair example", types.SOFTWARE, "", types.Sign, types.Verify)
	if err != nil {
		panic(err)
	}

	data := "Hello World !!!" // Data to sign
	format := types.Jws
	signResponse, err := kmsClient.Sign(context.Background(), okmsId, respECDSA.Id, &format, types.ES256, false, []byte(data))
	if err != nil {
		panic(err)
	}
	fmt.Println("Signature:", signResponse)

	result, err := kmsClient.Verify(context.Background(), okmsId, respECDSA.Id, types.ES256, false, []byte(data), signResponse)
	if err != nil {
		panic(err)
	}
	fmt.Println("Is valid:", result)

	// You can also instantiate an stdlib crypto.Signer
	signer, err := kmsClient.NewSigner(ctx, okmsId, respECDSA.Id)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256([]byte(data))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}

	valid := ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], signature)
	fmt.Println("Is valid:", valid)
}
