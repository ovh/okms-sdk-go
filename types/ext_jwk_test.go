package types

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJsonWebKey_OCT(t *testing.T) {
	key := [32]byte{}
	_, err := rand.Read(key[:])
	require.NoError(t, err)

	jwk, err := NewJsonWebKey(key[:], []CryptographicUsages{Encrypt, Decrypt}, "the-key")
	require.NoError(t, err)

	_, err = jwk.PublicKey()
	require.Error(t, err)

	assert.EqualValues(t, toBase64(new(big.Int).SetBytes(key[:])), jwk.K)
}

func TestNewJsonWebKey_RSA(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk, err := NewJsonWebKey(private, []CryptographicUsages{Sign, Verify}, "the-key")
	require.NoError(t, err)

	pubKey, err := jwk.PublicKey()
	require.NoError(t, err)
	assert.EqualValues(t, private.Public(), pubKey)
}

func TestNewJsonWebKey_ECDSA(t *testing.T) {
	tcs := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			private, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			jwk, err := NewJsonWebKey(private, []CryptographicUsages{Sign, Verify}, "the-key")
			require.NoError(t, err)

			pubKey, err := jwk.PublicKey()
			require.NoError(t, err)
			assert.EqualValues(t, private.Public(), pubKey)
		})
	}
}
