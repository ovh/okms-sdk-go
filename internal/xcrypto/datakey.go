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
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ovh/okms-sdk-go/internal/utils"
)

const DEFAULT_BLOCK_SIZE = 32 * 1024 // 32kB

var magicNumber = []byte("OKMSBLOB")

type KeyProvider interface {
	GenerateDataKey(ctx context.Context, name string, size int) (plain, encrypted []byte, err error)
	DecryptDataKey(ctx context.Context, key []byte) ([]byte, error)
}

type DatakeyAEADStream struct {
	kProv KeyProvider
}

func NewDatakeyAEADStream(prov KeyProvider) *DatakeyAEADStream {
	return &DatakeyAEADStream{
		kProv: prov,
	}
}

func (e *DatakeyAEADStream) SealTo(ctx context.Context, w io.Writer, aad []byte, blockSize int) (io.WriteCloser, error) {
	if blockSize <= 0 {
		blockSize = DEFAULT_BLOCK_SIZE
	}

	// Let's first ask the KMS to generate a new DK
	keyPlain, keyEncrypted, err := e.kProv.GenerateDataKey(ctx, "ephemeral.v2", 256)
	if err != nil {
		return nil, err
	}

	writer, err := NewAesGcmStreamWriter(w, keyPlain, aad, nil, blockSize)
	if err != nil {
		return nil, err
	}

	hdr := HeaderV2{
		key:       keyEncrypted,
		nonce:     writer.Seed(),
		blockSize: blockSize,
	}
	// Write the  header
	if err := writeHeaderV2(w, &hdr); err != nil {
		return nil, err
	}
	return writer, nil
}

func (e *DatakeyAEADStream) OpenFrom(ctx context.Context, r io.Reader, aad []byte) (io.Reader, error) {
	version, err := readVersion(r)
	if err != nil {
		return nil, err
	}

	switch version {
	case 2:
		r, err = e.decryptV2From(ctx, r, aad)
	default:
		err = fmt.Errorf("Invalid version '%d'", version)
	}
	return r, err
}

func (e *DatakeyAEADStream) decryptV2From(ctx context.Context, r io.Reader, aad []byte) (io.Reader, error) {
	hdr, err := readHeaderV2(r)
	if err != nil {
		return nil, err
	}
	keyPlain, err := e.kProv.DecryptDataKey(ctx, hdr.key)
	if err != nil {
		return nil, err
	}

	reader, err := NewAesGcmStreamReader(r, keyPlain, aad, hdr.nonce, hdr.blockSize)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

func readVersion(r io.Reader) (uint8, error) {
	blob := make([]byte, len(magicNumber)+1)
	if _, err := io.ReadFull(r, blob); err != nil {
		return 0, err
	}
	// Check the magic number
	if !bytes.HasPrefix(blob, magicNumber) {
		return 0, errors.New("Invalid file (magic number mismatch)")
	}
	return blob[len(magicNumber)], nil
}

type HeaderV2 struct {
	key       []byte
	nonce     []byte
	blockSize int
}

func readHeaderV2(r io.Reader) (HeaderV2, error) {
	header := HeaderV2{}
	// Extract the encrypted key length (int16)
	u16 := [2]byte{0, 0}
	if _, err := io.ReadFull(r, u16[:]); err != nil {
		return header, err
	}
	keyLen := int(binary.LittleEndian.Uint16(u16[:]))
	header.key = make([]byte, keyLen)
	if _, err := io.ReadFull(r, header.key); err != nil {
		return header, err
	}

	if _, err := io.ReadFull(r, u16[:]); err != nil {
		return header, err
	}
	nonceLen := int(binary.LittleEndian.Uint16(u16[:]))

	header.nonce = make([]byte, nonceLen)
	if _, err := io.ReadFull(r, header.nonce); err != nil {
		return header, err
	}

	var u32 [4]byte
	if _, err := io.ReadFull(r, u32[:]); err != nil {
		return header, err
	}
	header.blockSize = int(binary.LittleEndian.Uint32(u32[:]))

	return header, nil
}

func writeHeaderV2(out io.Writer, h *HeaderV2) error {
	if _, err := out.Write(magicNumber); err != nil {
		return err
	}
	if _, err := out.Write([]byte{2}); err != nil {
		return err
	}

	u16 := [2]byte{0, 0}
	binary.LittleEndian.PutUint16(u16[:], utils.ToUint16(len(h.key)))
	if _, err := out.Write(u16[:]); err != nil {
		return err
	}
	if _, err := out.Write(h.key); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(u16[:], utils.ToUint16(len(h.nonce)))
	if _, err := out.Write(u16[:]); err != nil {
		return err
	}
	if _, err := out.Write(h.nonce); err != nil {
		return err
	}
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], utils.ToUint32(h.blockSize))
	if _, err := out.Write(u32[:]); err != nil {
		return err
	}
	return nil
}
