// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

// Package types holds the REST API type definitions, including requests, responses, and enums.
package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// PublicKey convert the JWK public key into a go stdlib [crypto.PublicKey].
// It will be either a [*rsa.PublicKey] or a [*ecdsa.PublicKey].
func (key JsonWebKeyResponse) PublicKey() (crypto.PublicKey, error) {
	switch key.Kty {
	case RSA:
		e, err := parseBase64BigInt(key.E, "e")
		if err != nil {
			return nil, err
		}
		n, err := parseBase64BigInt(key.N, "n")
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{E: int(e.Int64()), N: n}, nil
	case EC:
		if key.Crv == nil {
			return nil, fmt.Errorf("Invalid JWK key: Parameter %q is missing", "crv")
		}
		crv, err := getCurve(*key.Crv)
		if err != nil {
			return nil, err
		}
		return parseEcPublicKey(crv, key.X, key.Y)
	default:
		return nil, fmt.Errorf("unsupported key type %s", key.Kty)
	}
}

// NewJsonWebKey creates a new JWK from a key. The accepted types are:
//   - [*rsa.PrivateKey] and [*rsa.PublicKey]
//   - [*ecdsa.PrivateKey] and [*ecdsa.PublicKey]
//   - []byte for symmetric keys
func NewJsonWebKey(key any, ops []CryptographicUsages, id string) (JsonWebKeyResponse, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		key.Precompute()
		return JsonWebKeyResponse{
			Kid:    id,
			KeyOps: &ops,
			Kty:    RSA,
			D:      toBase64(key.D),
			E:      toBase64(big.NewInt(int64(key.E))),
			N:      toBase64(key.N),
			P:      toBase64(key.Primes[0]),
			Q:      toBase64(key.Primes[1]),
			Dp:     toBase64(key.Precomputed.Dp),
			Dq:     toBase64(key.Precomputed.Dq),
			Qi:     toBase64(key.Precomputed.Qinv),
		}, nil
	case *rsa.PublicKey:
		return JsonWebKeyResponse{
			Kid:    id,
			KeyOps: &ops,
			Kty:    RSA,
			E:      toBase64(big.NewInt(int64(key.E))),
			N:      toBase64(key.N),
		}, nil
	case *ecdsa.PrivateKey:
		curve := Curves(key.Curve.Params().Name)
		d, err := key.Bytes()
		if err != nil {
			return JsonWebKeyResponse{}, err
		}
		x, y, err := ecPointToBase64(&key.PublicKey)
		if err != nil {
			return JsonWebKeyResponse{}, err
		}
		return JsonWebKeyResponse{
			Kid:    id,
			KeyOps: &ops,
			Kty:    EC,
			D:      bytesToBase64(d),
			X:      x,
			Y:      y,
			Crv:    &curve,
		}, nil
	case *ecdsa.PublicKey:
		curve := Curves(key.Curve.Params().Name)
		x, y, err := ecPointToBase64(key)
		if err != nil {
			return JsonWebKeyResponse{}, err
		}
		return JsonWebKeyResponse{
			Kid:    id,
			KeyOps: &ops,
			Kty:    EC,
			X:      x,
			Y:      y,
			Crv:    &curve,
		}, nil
	case []byte:
		return JsonWebKeyResponse{
			Kid:    id,
			KeyOps: &ops,
			Kty:    Oct,
			K:      toBase64(new(big.Int).SetBytes(key)),
		}, nil
	default:
		return JsonWebKeyResponse{}, fmt.Errorf("Unsupported key type: %T", key)
	}
}

func parseBase64Bytes(v *string, name string) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("Invalid JWK key: Parameter %q is missing", name)
	}
	return base64.RawURLEncoding.DecodeString(*v)
}

func parseBase64BigInt(v *string, name string) (*big.Int, error) {
	v64, err := parseBase64Bytes(v, name)
	if err != nil {
		return nil, err
	}
	return big.NewInt(0).SetBytes(v64), nil
}

func toBase64(n *big.Int) *string {
	if n == nil {
		return nil
	}
	return bytesToBase64(n.Bytes())
}

func bytesToBase64(b []byte) *string {
	v := base64.RawURLEncoding.EncodeToString(b)
	return &v
}

// ecPointToBase64 encodes the affine coordinates of an EC public key as the
// base64url "x" and "y" JWK parameters.
func ecPointToBase64(key *ecdsa.PublicKey) (x, y *string, err error) {
	point, err := key.Bytes()
	if err != nil {
		return nil, nil, err
	}
	// point is the SEC 1 uncompressed point encoding: 0x04 || x || y
	size := (key.Curve.Params().BitSize + 7) / 8
	if len(point) != 1+2*size || point[0] != 4 {
		return nil, nil, fmt.Errorf("unexpected EC public key encoding")
	}
	return bytesToBase64(point[1 : 1+size]), bytesToBase64(point[1+size:]), nil
}

// parseEcPublicKey builds an EC public key from the base64url "x" and "y" JWK parameters.
func parseEcPublicKey(crv elliptic.Curve, x, y *string) (*ecdsa.PublicKey, error) {
	size := (crv.Params().BitSize + 7) / 8
	// SEC 1 uncompressed point encoding: 0x04 || x || y
	point := make([]byte, 1+2*size)
	point[0] = 4
	if err := fillCoordinate(point[1:1+size], x, "x"); err != nil {
		return nil, err
	}
	if err := fillCoordinate(point[1+size:], y, "y"); err != nil {
		return nil, err
	}
	return ecdsa.ParseUncompressedPublicKey(crv, point)
}

// fillCoordinate decodes a base64url JWK coordinate into dst, left padded to its size.
func fillCoordinate(dst []byte, v *string, name string) error {
	raw, err := parseBase64Bytes(v, name)
	if err != nil {
		return err
	}
	if len(raw) > len(dst) {
		return fmt.Errorf("Invalid JWK key: Parameter %q is too large", name)
	}
	copy(dst[len(dst)-len(raw):], raw) // coordinates may have lost their leading zeroes
	return nil
}

func getCurve(crv Curves) (elliptic.Curve, error) {
	switch crv {
	// case "P-224":
	// 	return elliptic.P224(), nil
	case P256:
		return elliptic.P256(), nil
	case P384:
		return elliptic.P384(), nil
	case P521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve type %s", crv)
	}
}
