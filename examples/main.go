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

	"github.com/ovh/okms-sdk-go"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	cert, err := tls.LoadX509KeyPair(os.Getenv("KMS_CLIENT_CERT_FILE"), os.Getenv("KMS_CLIENT_KEY_FILE"))
	if err != nil {
		panic(err)
	}
	httpClient := http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}},
	}
	kmsClient, err := okms.NewRestAPIClientWithHttp("https://eu-west-rbx.okms.ovh.net", &httpClient)
	if err != nil {
		panic(err)
	}

	generateKeys(ctx, kmsClient)
	encryptDecrypt(ctx, kmsClient)
	signVerify(ctx, kmsClient)
	dataKeyEncryptDecrypt(ctx, kmsClient)
	listKeys(ctx, kmsClient)
	getKey(ctx, kmsClient)
}
