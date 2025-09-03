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
	"crypto/tls"
	"net/http"
	"os"
	"os/signal"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
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

	generateKeys(ctx, kmsClient, okmsId)
	encryptDecrypt(ctx, kmsClient, okmsId)
	signVerify(ctx, kmsClient, okmsId)
	dataKeyEncryptDecrypt(ctx, kmsClient, okmsId)
	listKeys(ctx, kmsClient, okmsId)
	getKey(ctx, kmsClient, okmsId)
	dataKeyEncryptStream(ctx, kmsClient, okmsId)
	dataKeyDecryptStream(ctx, kmsClient, okmsId)
}
