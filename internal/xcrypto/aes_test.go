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
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAesGcmStream_EncryptDecrypt(t *testing.T) {
	data := []byte("foobar")
	key := sha256.Sum256([]byte("mykey"))
	seq1, err := NewAesGcmStream(key[:], nil)
	require.NoError(t, err)
	seq2, err := NewAesGcmStream(key[:], seq1.Seed())
	require.NoError(t, err)

	encrypted := seq1.Seal(nil, data, nil)
	decrypted, err := seq2.Open(nil, encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)

	_, err = seq2.Open(nil, encrypted, nil)
	require.Error(t, err)
}

func TestAesGcmReadWrite(t *testing.T) {
	const BLOCK_SIZE = 32 * 1024
	tcs := []struct {
		name string
		size int
	}{
		{"1B", 1},
		{"32B", 32},
		{"32kB", 32 * 1024},
		{"32kB-no-overflow", 32*1024 - 16}, // That's exactly 1 block. No overflow.
		{"32MB", 32 * 1024 * 1024},
		{"32MB-minus-16B", 32*1024*1024 - 16},
		{"32MB-no-overflow", (32*1024 - 16) * 1024}, // Multiple blocks without overflow
		{"100MB", 100 * 1024 * 1024},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			check := make([]byte, tc.size)
			_, err := rand.Read(check)
			require.NoError(t, err)

			data := bytes.NewBuffer(check)
			result := bytes.Buffer{}
			key := sha256.Sum256([]byte("mykey"))

			writer, err := NewAesGcmStreamWriter(&result, key[:], nil, nil, BLOCK_SIZE)
			require.NoError(t, err)

			n, err := io.Copy(writer, data)
			require.NoError(t, err)
			assert.NoError(t, writer.Close())

			assert.Zero(t, data.Len())
			assert.NotZero(t, result.Len())
			assert.EqualValues(t, len(check), n)

			reader, err := NewAesGcmStreamReader(&result, key[:], nil, writer.Seed(), BLOCK_SIZE)
			require.NoError(t, err)

			_, err = io.Copy(data, reader)
			require.NoError(t, err)

			assert.Equal(t, check, data.Bytes())
		})
	}
}

func TestAesGcmReadWrite_BadParams(t *testing.T) {
	key := sha256.Sum256([]byte("mykey"))
	_, err := NewAesGcmStreamReader(nil, nil, nil, nil, 0)
	assert.Error(t, err)
	_, err = NewAesGcmStreamWriter(nil, nil, nil, nil, 0)
	assert.Error(t, err)

	_, err = NewAesGcmStreamReader(nil, key[:], nil, nil, 0)
	assert.Error(t, err)
	_, err = NewAesGcmStreamWriter(nil, key[:], nil, nil, 0)
	assert.Error(t, err)

	assert.Panics(t, func() { NewAesGcmStreamReader(nil, key[:], nil, []byte("foobar"), 12) })
	assert.Panics(t, func() { NewAesGcmStreamWriter(nil, key[:], nil, []byte("foobar"), 12) })
}

func TestAesGcmReadWrite_AfterClose(t *testing.T) {
	const BLOCK_SIZE = 32 * 1024
	rw := &bytes.Buffer{}
	key := sha256.Sum256([]byte("mykey"))
	writer, err := NewAesGcmStreamWriter(rw, key[:], nil, nil, BLOCK_SIZE)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, writer.Close())
	_, err = writer.Write([]byte("foobar"))
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestAesGcm_Truncate_Protect(t *testing.T) {
	const BLOCK_SIZE = 32 * 1024
	dst := &bytes.Buffer{}
	key := sha256.Sum256([]byte("mykey"))
	writer, err := NewAesGcmStreamWriter(dst, key[:], nil, nil, BLOCK_SIZE)
	require.NoError(t, err)

	data := make([]byte, 10*BLOCK_SIZE)
	_, err = rand.Read(data)
	require.NoError(t, err)
	n, err := writer.Write(data)
	require.Equal(t, n, len(data))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	// Truncate the last block. The stream can still be decrypted, but truncation will be detected.
	dst.Truncate(8 * BLOCK_SIZE)

	reader, err := NewAesGcmStreamReader(dst, key[:], nil, writer.Seed(), BLOCK_SIZE)
	require.NoError(t, err)
	_, err = io.ReadAll(reader)
	// Message last block is removed, but truncation is detected when reading the whole message
	require.ErrorContains(t, err, "cipher: message authentication failed")
	require.EqualValues(t, 2, reader.aead.seq.final) // Ensure we went through finalization
}

func TestAesGcm_Unexpected_EOF(t *testing.T) {
	const BLOCK_SIZE = 32 * 1024
	dst := &bytes.Buffer{}
	key := sha256.Sum256([]byte("mykey"))
	writer, err := NewAesGcmStreamWriter(dst, key[:], nil, nil, BLOCK_SIZE)
	require.NoError(t, err)

	data := make([]byte, 10*BLOCK_SIZE)
	_, err = rand.Read(data)
	require.NoError(t, err)
	n, err := writer.Write(data)
	require.Equal(t, n, len(data))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	// Truncate the last block. The last block is corrupted and cannot be decrypted
	dst.Truncate(8*BLOCK_SIZE + 100)

	reader, err := NewAesGcmStreamReader(dst, key[:], nil, writer.Seed(), BLOCK_SIZE)
	require.NoError(t, err)
	_, err = io.ReadAll(reader)
	// Message last block is removed, but truncation is detected when reading the whoe message
	require.ErrorContains(t, err, "cipher: message authentication failed")
}

func TestAesGcm_Reordering_Protect(t *testing.T) {
	const BLOCK_SIZE = 32 * 1024
	dst := &bytes.Buffer{}
	key := sha256.Sum256([]byte("mykey"))
	writer, err := NewAesGcmStreamWriter(dst, key[:], nil, nil, BLOCK_SIZE)
	require.NoError(t, err)

	data := make([]byte, 10*BLOCK_SIZE)
	_, err = rand.Read(data)
	require.NoError(t, err)
	n, err := writer.Write(data)
	require.Equal(t, n, len(data))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	// Swap 2 blocks. The stream can still be decrypted until the first swapped block.
	b := dst.Bytes()
	tmp := [BLOCK_SIZE]byte{}
	// Swap 2 blocks block
	copy(tmp[:], b[8*BLOCK_SIZE:9*BLOCK_SIZE])
	copy(b[8*BLOCK_SIZE:9*BLOCK_SIZE], b[3*BLOCK_SIZE:4*BLOCK_SIZE])
	copy(b[3*BLOCK_SIZE:4*BLOCK_SIZE], tmp[:])

	reader, err := NewAesGcmStreamReader(dst, key[:], nil, writer.Seed(), BLOCK_SIZE)
	require.NoError(t, err)
	_, err = io.ReadAll(reader)
	require.ErrorContains(t, err, "cipher: message authentication failed")
}
