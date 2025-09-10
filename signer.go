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
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/types"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// NewSigner creates a new [crypto.Signer] for the given key-pair.
//
// NewSigner cannot be used with symetric keys.
func (client *Client) NewSigner(ctx context.Context, okmsId, serviceKeyID uuid.UUID) (crypto.Signer, error) {
	k, err := client.ExportJwkPublicKey(ctx, okmsId, serviceKeyID)
	if err != nil {
		return nil, err
	}
	return newSigner(client, okmsId, k)
}

// newSigner creates a new [crypto.Signer] using the given public JsonWebKey and
// its remote private key.
//
// newSigner cannot be used with symetric keys.
func newSigner(api SignatureApi, okmsId uuid.UUID, jwk *types.JsonWebKeyResponse) (crypto.Signer, error) {
	pubKey, err := jwk.PublicKey()
	if err != nil {
		return nil, err
	}

	return &jwkSigner{
		okmsId:             okmsId,
		JsonWebKeyResponse: jwk,
		api:                api,
		pubKey:             pubKey,
	}, nil
}

type jwkSigner struct {
	*types.JsonWebKeyResponse
	okmsId uuid.UUID
	api    SignatureApi
	pubKey crypto.PublicKey
}

// Public returns the public key corresponding to the opaque,
// private key.
func (sig *jwkSigner) Public() crypto.PublicKey {
	return sig.pubKey
}

// Sign signs digest with the private key, possibly using entropy from
// rand. For an RSA key, the resulting signature should be either a
// PKCS #1 v1.5 or PSS signature (as indicated by opts). For an (EC)DSA
// key, it should be a DER-serialized, ASN.1 signature structure.
//
// Hash implements the SignerOpts interface and, in most cases, one can
// simply pass in the hash function used as opts. Sign may also attempt
// to type assert opts to other types in order to obtain algorithm
// specific values. See the documentation in each package for details.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest) and the hash function (as opts) to Sign.
func (sign *jwkSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch sign.Kty {
	case types.EC:
		// ECDSA signature
		return sign.signEcdsa(digest, opts.HashFunc())
	case types.RSA:
		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			// RSA PSS signature
			return sign.signRsaPss(digest, pssOpts)
		} else {
			// PKCS1 v1.5 signature
			return sign.signRsaPkcs15(digest, opts.HashFunc())
		}
	}
	return nil, errors.New("Invalid key type")
}

func (sign *jwkSigner) signRsaPkcs15(digest []byte, hash crypto.Hash) ([]byte, error) {
	return sign.doSign(digest, hash, "RS")
}

func (sign *jwkSigner) signRsaPss(digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	// The size of the salt value is the same size as the hash function output as defined in https://www.rfc-editor.org/rfc/rfc7518#section-3.5
	if opts.SaltLength != rsa.PSSSaltLengthAuto && opts.SaltLength != rsa.PSSSaltLengthEqualsHash && opts.SaltLength != opts.Hash.Size() {
		return nil, errors.New("Invalid PSS salt length")
	}
	return sign.doSign(digest, opts.HashFunc(), "PS")
}

func (sign *jwkSigner) signEcdsa(digest []byte, hash crypto.Hash) ([]byte, error) {
	sig, err := sign.doSign(digest, hash, "ES")
	if err != nil {
		return nil, err
	}
	r, s := sig[:len(sig)/2], sig[len(sig)/2:]
	asn1Sig, err := encodeEcdsaSignature(r, s)
	if err != nil {
		return nil, err
	}
	return asn1Sig, nil
}

func (sign *jwkSigner) doSign(digest []byte, hash crypto.Hash, algPrefix string) ([]byte, error) {
	alg, err := getJwaAlgName(algPrefix, hash)
	if err != nil {
		return nil, err
	}

	keyId, err := uuid.Parse(sign.Kid)
	if err != nil {
		return nil, fmt.Errorf("Key ID %q is not a valid UUID", sign.Kid)
	}
	rawFormat := types.Raw
	resp, err := sign.api.Sign(context.Background(), sign.okmsId, keyId, &rawFormat, alg, true, digest)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp)
}

func encodeEcdsaSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

func getJwaAlgName(prefix string, hash crypto.Hash) (types.DigitalSignatureAlgorithms, error) {
	alg := ""
	switch hash {
	case crypto.SHA256:
		alg = "256"
	case crypto.SHA384:
		alg = "384"
	case crypto.SHA512:
		alg = "512"
	default:
		return "", errors.New("Unsupported hash function")
	}
	return types.DigitalSignatureAlgorithms(prefix + alg), nil
}
