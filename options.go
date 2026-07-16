// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package okms

import (
	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/internal/utils"
	"github.com/ovh/okms-sdk-go/types"
)

type ServiceKeyOption func(request *types.CreateImportServiceKeyRequest)

func WithKeyID(id uuid.UUID) ServiceKeyOption {
	return func(req *types.CreateImportServiceKeyRequest) {
		req.Id = utils.PtrTo(id.String())
	}
}

// WithExtractable sets whether the key and information about it can be extracted from the KMS.
// When set to false, the key material cannot be exported in any form (plain or wrapped).
// The default is true, and once set to false it cannot be reverted to true.
func WithExtractable(extractable bool) ServiceKeyOption {
	return func(req *types.CreateImportServiceKeyRequest) {
		req.Extractable = utils.PtrTo(extractable)
	}
}
