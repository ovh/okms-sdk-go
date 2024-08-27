// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

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
func (key JsonWebKey) PublicKey() (crypto.PublicKey, error) {
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
		x, err := parseBase64BigInt(key.X, "x")
		if err != nil {
			return nil, err
		}
		y, err := parseBase64BigInt(key.Y, "y")
		if err != nil {
			return nil, err
		}
		crv, err := getCurve(*key.Crv)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{X: x, Y: y, Curve: crv}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %s", key.Kty)
	}
}

// NewJsonWebKey creates a new JWK private key from either a [*rsa.PrivateKey], a [*ecdsa.PrivateKey] or a []byte symmetric key.
func NewJsonWebKey(privateKey any, ops []CryptographicUsages, id string) (JsonWebKey, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		key.Precompute()
		return JsonWebKey{
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
	case *ecdsa.PrivateKey:
		curve := Curves(key.Curve.Params().Name)
		return JsonWebKey{
			Kid:    id,
			KeyOps: &ops,
			Kty:    EC,
			D:      toBase64(key.D),
			X:      toBase64(key.X),
			Y:      toBase64(key.Y),
			Crv:    &curve,
		}, nil
	case []byte:
		return JsonWebKey{
			Kid:    id,
			KeyOps: &ops,
			Kty:    Oct,
			K:      toBase64(new(big.Int).SetBytes(key)),
		}, nil
	default:
		return JsonWebKey{}, fmt.Errorf("Unsupported key type: %T", privateKey)
	}
}

func parseBase64BigInt(v *string, name string) (*big.Int, error) {
	if v == nil {
		return nil, fmt.Errorf("Invalid JWK key: Parameter %q is missing", name)
	}
	v64, err := base64.RawURLEncoding.DecodeString(*v)
	if err != nil {
		return nil, err
	}
	return big.NewInt(0).SetBytes(v64), nil
}

func toBase64(n *big.Int) *string {
	if n == nil {
		return nil
	}
	v := base64.RawURLEncoding.EncodeToString(n.Bytes())
	return &v
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
