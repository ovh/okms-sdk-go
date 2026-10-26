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
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/internal/utils"
	"github.com/ovh/okms-sdk-go/mocks"
	"github.com/ovh/okms-sdk-go/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestImportWrappedServiceKey(t *testing.T) {
	okmsId := uuid.New()
	wrappingKeyID := uuid.New()
	ops := []types.CryptographicUsages{types.Encrypt, types.Decrypt}
	resp := &types.GetServiceKeyResponse{Id: uuid.New()}

	tcs := []struct {
		name      string
		keyFormat types.KeyFormatTypes
		opts      []ServiceKeyOption
		expected  types.CreateImportServiceKeyRequest
	}{
		{
			name:      "software",
			keyFormat: types.RAW,
			expected: types.CreateImportServiceKeyRequest{
				Name:       "key",
				Operations: &ops,
				WrappedKeys: &[]types.WrappedKeyEntry{
					{Ciphertext: "jwe", KeyFormatType: utils.PtrTo(types.RAW), WrappingKeyId: wrappingKeyID},
				},
			},
		},
		{
			name:      "hsm-protection-level",
			keyFormat: types.RAW,
			opts:      []ServiceKeyOption{WithProtectionLevel(types.HSM)},
			expected: types.CreateImportServiceKeyRequest{
				Name:            "key",
				Operations:      &ops,
				ProtectionLevel: utils.PtrTo(types.HSM),
				WrappedKeys: &[]types.WrappedKeyEntry{
					{Ciphertext: "jwe", KeyFormatType: utils.PtrTo(types.RAW), WrappingKeyId: wrappingKeyID},
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			mc := mocks.NewAPIMock(t)
			client := Client{mc}

			mc.EXPECT().CreateImportServiceKey(mock.Anything, okmsId, (*types.KeyFormats)(nil), tc.expected).
				Return(resp, nil).
				Once()

			k, err := client.ImportWrappedServiceKey(context.Background(), okmsId, wrappingKeyID, "jwe", tc.keyFormat, "key", "", ops, tc.opts...)
			require.NoError(t, err)
			require.Equal(t, resp, k)
		})
	}
}

func TestImportWrappedServiceKey_HSM(t *testing.T) {
	okmsId := uuid.New()
	wrappingKeyID := uuid.New()
	keyID := uuid.New()
	ops := []types.CryptographicUsages{types.Encrypt, types.Decrypt}
	resp := &types.GetServiceKeyResponse{Id: uuid.New()}

	mc := mocks.NewAPIMock(t)
	client := Client{mc}

	// The key format is omitted, and the type and protection level are set.
	mc.EXPECT().CreateImportServiceKey(mock.Anything, okmsId, (*types.KeyFormats)(nil), types.CreateImportServiceKeyRequest{
		Id:              utils.PtrTo(keyID.String()),
		Name:            "key",
		Operations:      &ops,
		ProtectionLevel: utils.PtrTo(types.HSM),
		Type:            utils.PtrTo(types.Oct),
		WrappedKeys: &[]types.WrappedKeyEntry{
			{Ciphertext: "jwe", WrappingKeyId: wrappingKeyID},
		},
	}).
		Return(resp, nil).
		Once()

	k, err := client.ImportWrappedServiceKey(context.Background(), okmsId, wrappingKeyID, "jwe", "", "key", "", ops, WithKeyID(keyID), WithProtectionLevel(types.HSM), WithKeyType(types.Oct))
	require.NoError(t, err)
	require.Equal(t, resp, k)
}
