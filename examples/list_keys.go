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
