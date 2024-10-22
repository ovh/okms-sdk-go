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
	"crypto/cipher"
	"fmt"
	"io"
)

// AEADStream implements a common approach which is to follow the [STREAM construction](https://eprint.iacr.org/2015/189.pdf) which has
// [formally been proven to be secure](https://eprint.iacr.org/2020/1019.pdf) and allows for random access.
//
// In a nutshell, the construct applies the AEAD encryption to blocks of fixed size. Each block is encrypted with the same key and AAD, only the nonce changes.
// In order to ensure a nonce is never used twice with the key, it is implemented as a counter (protecting against block reordering) concatenated to a randomly
// chosen nonce prefix, with an additional byte to identify the last block (protecting against truncation).
//
// Considering AES-GCM: As the nonce is 12 bytes (96 bits) and since there is a hard limit of 2^32 nonces for a single key, the counter doesn't need to be more than 4 bytes. The nonce prefix is then 7 bytes, the counter 4 bytes, and 1 byte for identifying the final block = 12 bytes. The last byte used to identify the final block is very important as it protects the data against truncate attacks. The counter protects the stream against reordering attacks.
//
// A single key can be used to encrypt multiple stream as long as the nonce prefix is unique. There may be a higher risks of collisions in distributed environments where the 7 bytes of the nonce prefix may have to be generated randomly. An example of mitigation is to reserve a byte in the nonce prefix to identify the encrypting equipment.
type AEADStream struct {
	inner cipher.AEAD
	seq   *NonceSequence
}

func NewAEADStream(aead cipher.AEAD, seed []byte) *AEADStream {
	return &AEADStream{
		inner: aead,
		seq:   NewNonceSequence(aead.NonceSize(), seed),
	}
}

// Seed returns the seed used by the nonce sequence.
func (s *AEADStream) Seed() []byte {
	return s.seq.Seed()
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (s *AEADStream) Overhead() int {
	return s.inner.Overhead()
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice.
//
// Setting final to true marks the block to be the final one. Meaning that this call to Seal()
// will be (and must be) the last one. The Nonce used for encrypting this last block will have the finalization bit
// set to 1.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (s *AEADStream) Seal(dst, plaintext, additionalData []byte, final bool) []byte {
	return s.inner.Seal(dst, s.seq.Next(final), plaintext, additionalData)
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The additional data must match the
// value passed to Seal.
//
// Setting final to true marks the block to be the final one. Meaning that this call to Open()
// will be (and must be) the last one. The Nonce used for decrypting this last block will have the finalization bit
// set to 1.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (s *AEADStream) Open(dst, ciphertext, additionalData []byte, final bool) ([]byte, error) {
	return s.inner.Open(dst, s.seq.Next(final), ciphertext, additionalData)
}

// Finalize marks the next block to be the final one. Meaning that the next call to Open() or Seal()
// will be (and must be) the last one. The Nonce used for encrypting the last block will have the finalization bit
// set to 1.

// AEADStreamReader wraps a [AEADStream] and an [io.Reader] into another [io.Reader], decrypting data on the fly.
type AEADStreamReader struct {
	aead      *AEADStream
	source    io.Reader
	buffer    *bytes.Buffer
	aad       []byte
	blockSize int
	next      byte
	hasMore   bool
}

func NewAEADStreamReader(aead *AEADStream, source io.Reader, aad []byte, blockSize int) (*AEADStreamReader, error) {
	if blockSize <= aead.Overhead() {
		return nil, fmt.Errorf("Block size must be > %d bytes", aead.Overhead())
	}
	return &AEADStreamReader{
		aead:      aead,
		source:    source,
		aad:       aad,
		blockSize: blockSize,
		buffer:    new(bytes.Buffer),
	}, nil
}

func (aes *AEADStreamReader) Read(b []byte) (int, error) {
	// Return leftovers from previous round, if any
	if aes.buffer.Len() > 0 {
		return aes.buffer.Read(b)
	}

	// Read exactly 1 block + maybe 1 byte so we can know if there are more blocks to come.
	aes.buffer.Grow(aes.blockSize + 1)
	buf := aes.buffer.AvailableBuffer()[:aes.blockSize+1]
	off := 0
	// If we already got the first byte of the next block, push it to the buffer
	if aes.hasMore {
		off = 1
		buf[0] = aes.next
	}
	n, err := io.ReadFull(aes.source, buf[off:])
	if err != nil && n <= 0 {
		if off == 0 && err == io.EOF {
			// EOF is reached only if there is no more data,
			// and not leftover in the buffer
			return 0, err
		}
	}
	n += off
	aes.hasMore = false

	final := false

	// Verify if we got the first byte of the next block, just to check if there is another block
	// so that if it's the last block, it will be marked cryptographically as the last.
	// It prevents truncate attacks.
	if n > aes.blockSize {
		// There's another block, so just set hasMore to true so next time we know
		// that we already got the first byte of the block
		aes.next = buf[aes.blockSize]
		n -= 1
		aes.hasMore = true
	} else {
		// If we could not read a full block + 1 byte, it means that this one is the last one
		// so we can make the finalization.
		final = true
	}

	// Decrypt the block in place
	buf, err = aes.aead.Open(buf[:0], buf[:n], aes.aad, final)
	if err != nil {
		return 0, err
	}
	// Write the decrypted output to the buffer
	_, _ = aes.buffer.Write(buf) // err is always nil

	// Read from the internal buffer
	return aes.buffer.Read(b)
}

// AEADStreamWriter wraps a [AEADStream] and an [io.Writer] into an [io.WriteCloser], encrytping data on the fly.
// The returned [io.WriteCloser] must be closed or the last encrypted block of data will never be written. But closing it
// will not close the wrapped [io.Writer].
type AEADStreamWriter struct {
	aead      *AEADStream
	dest      io.Writer
	buffer    *bytes.Buffer
	aad       []byte
	blockSize int
	closed    bool
}

func NewAEADStreamWriter(aead *AEADStream, dst io.Writer, aad []byte, blockSize int) (*AEADStreamWriter, error) {
	if blockSize <= aead.Overhead() {
		return nil, fmt.Errorf("Block size must be > %d bytes", aead.Overhead())
	}
	return &AEADStreamWriter{
		aead:      aead,
		dest:      dst,
		aad:       aad,
		blockSize: blockSize - aead.Overhead(),
		buffer:    new(bytes.Buffer),
	}, nil
}

func (aes *AEADStreamWriter) Write(b []byte) (int, error) {
	if aes.closed {
		return 0, io.ErrClosedPipe
	}
	buff := bytes.NewBuffer(b)
	for buff.Len() > 0 {
		// Read up to block size + 1 (to check if there's another block following)
		toRead := aes.blockSize + 1 - aes.buffer.Len()
		_, _ = aes.buffer.Write(buff.Next(toRead)) // err is always nil
		// If we have buffered at least a full block of data + the first byte of the next block (indicating this is not the final block)
		// encrypt the block and flush it.
		if aes.buffer.Len() > aes.blockSize {
			if err := aes.flush(false); err != nil {
				return 0, err
			}
		}
	}
	return len(b), nil
}

func (aes *AEADStreamWriter) Seed() []byte {
	return aes.aead.Seed()
}

func (aes *AEADStreamWriter) flush(final bool) error {
	if aes.buffer.Len() == 0 {
		return nil
	}
	// Grow buffer so the encryption tag will fit
	aes.buffer.Grow(aes.aead.Overhead())

	// Check if there is the first byte of next block in the buffer
	// and save it outside of it for later or it will be overwritten during encryption.
	// It is later added back at the beginning of the buffer
	var left byte
	var hasLeft bool
	if aes.buffer.Len() > aes.blockSize {
		left = aes.buffer.Bytes()[aes.buffer.Len()-1]
		aes.buffer.Truncate(aes.buffer.Len() - 1)
		hasLeft = true
	}

	// Encrypt in place
	blob := aes.aead.Seal(aes.buffer.Bytes()[:0], aes.buffer.Bytes(), aes.aad, final)
	// Write the encrypted data block to the underlying writer
	if _, err := aes.dest.Write(blob); err != nil {
		return err
	}
	// Then reset the buffer
	aes.buffer.Reset()
	if hasLeft {
		// Put the first byte of next block if any
		_ = aes.buffer.WriteByte(left)
	}
	return nil
}

func (aes *AEADStreamWriter) Close() error {
	if aes.closed {
		return nil
	}
	aes.closed = true
	// Mark the block as the final one.
	if err := aes.flush(true); err != nil {
		return err
	}
	// Check if underlying stream can be flushed, and flush it
	if flushable, ok := aes.dest.(interface{ Flush() error }); ok {
		return flushable.Flush()
	}
	return nil
}
