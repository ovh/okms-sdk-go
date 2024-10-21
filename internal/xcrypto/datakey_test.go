// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package xcrypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var key = hexbyte("bd1bd535add8e80d059e04e8d7436433a16666015414f62cda479472a96881b0")

type MockKeyProvider struct {
	mock.Mock
}

var _ KeyProvider = &MockKeyProvider{}

// DecryptDataKey implements KeyProvider.
func (m *MockKeyProvider) DecryptDataKey(ctx context.Context, key []byte) ([]byte, error) {
	r := m.Called(ctx, key)
	return r.Get(0).([]byte), r.Error(1)
}

// GenerateDataKey implements KeyProvider.
func (m *MockKeyProvider) GenerateDataKey(ctx context.Context, name string, size int) (plain []byte, encrypted []byte, err error) {
	r := m.Called(ctx, name, size)
	return r.Get(0).([]byte), r.Get(1).([]byte), r.Error(2)
}

func randomKey(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func TestEncryptDecryptV2(t *testing.T) {
	msg := []byte("Hello World !!!")
	encryptedKey := []byte("encrypted")
	kctx := []byte("keyctx")

	kprov := new(MockKeyProvider)
	stream := NewDatakeyAEADStream(kprov)

	kprov.On("GenerateDataKey", mock.Anything, "ephemeral.v2", 256).Return(key, encryptedKey, nil).Once()

	dest := &bytes.Buffer{}
	wr, err := stream.SealTo(context.Background(), dest, kctx, 1024)
	require.NoError(t, err)
	require.NotNil(t, wr)

	_, err = wr.Write(msg)
	require.NoError(t, err)
	assert.NoError(t, wr.Close())

	assert.Positive(t, dest.Len())
	kprov.AssertExpectations(t)

	kprov.On("DecryptDataKey", mock.Anything, encryptedKey).Return(key, nil).Once()
	rd, err := stream.OpenFrom(context.Background(), dest, kctx)
	require.NoError(t, err)
	plain, err := io.ReadAll(rd)
	assert.NoError(t, err)
	assert.Equal(t, msg, plain)
	kprov.AssertExpectations(t)
}
