package okms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/mocks"
	"github.com/ovh/okms-sdk-go/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSigner_RSA(t *testing.T) {
	api := mocks.NewAPIMock(t)
	client := Client{api}
	okmsId := uuid.New()
	keyId := uuid.New()
	format := types.Jwk

	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk, err := types.NewJsonWebKey(pKey, []types.CryptographicUsages{types.Sign, types.Verify}, keyId.String())
	require.NoError(t, err)

	api.EXPECT().GetServiceKey(mock.Anything, okmsId, keyId, &format).
		Return(&types.GetServiceKeyResponse{
			Attributes: &map[string]interface{}{"state": "active"},
			Keys:       &[]types.JsonWebKeyResponse{jwk},
		}, nil).
		Once()

	signer, err := client.NewSigner(context.Background(), okmsId, keyId)
	require.NoError(t, err)
	require.Equal(t, pKey.Public(), signer.Public())

	tcs := []struct {
		alg  types.DigitalSignatureAlgorithms
		hash crypto.SignerOpts
	}{
		{alg: types.RS256, hash: crypto.SHA256},
		{alg: types.RS384, hash: crypto.SHA384},
		{alg: types.RS512, hash: crypto.SHA512},
		{alg: types.PS256, hash: &rsa.PSSOptions{Hash: crypto.SHA256}},
		{alg: types.PS384, hash: &rsa.PSSOptions{Hash: crypto.SHA384}},
		{alg: types.PS512, hash: &rsa.PSSOptions{Hash: crypto.SHA512}},
	}

	for _, tc := range tcs {
		t.Run(string(tc.alg), func(t *testing.T) {
			hf := tc.hash.HashFunc().New()
			hf.Write([]byte("the message"))
			digest := hf.Sum(nil)

			var rawsig []byte
			var err error
			if strings.HasPrefix(string(tc.alg), "RS") {
				rawsig, err = rsa.SignPKCS1v15(rand.Reader, pKey, tc.hash.HashFunc(), digest)
			} else {
				rawsig, err = rsa.SignPSS(rand.Reader, pKey, tc.hash.HashFunc(), digest, tc.hash.(*rsa.PSSOptions))
			}
			require.NoError(t, err)

			rawFormat := types.Raw
			api.EXPECT().Sign(mock.Anything, okmsId, keyId, &rawFormat, tc.alg, true, mock.Anything).
				Return(base64.StdEncoding.EncodeToString(rawsig), nil).
				Once()
			sig, err := signer.Sign(rand.Reader, digest, tc.hash)
			require.NoError(t, err)
			require.Equal(t, rawsig, sig)
		})
	}
}

func TestSigner_ECDSA(t *testing.T) {
	api := mocks.NewAPIMock(t)
	client := Client{api}
	okmsId := uuid.New()
	keyId := uuid.New()
	format := types.Jwk

	pKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk, err := types.NewJsonWebKey(pKey, []types.CryptographicUsages{types.Sign, types.Verify}, keyId.String())
	require.NoError(t, err)

	api.EXPECT().GetServiceKey(mock.Anything, okmsId, keyId, &format).
		Return(&types.GetServiceKeyResponse{
			Attributes: &map[string]interface{}{"state": "active"},
			Keys:       &[]types.JsonWebKeyResponse{jwk},
		}, nil).
		Once()

	signer, err := client.NewSigner(context.Background(), okmsId, keyId)
	require.NoError(t, err)
	require.Equal(t, pKey.Public(), signer.Public())

	tcs := []struct {
		alg  types.DigitalSignatureAlgorithms
		hash crypto.SignerOpts
	}{
		{alg: types.ES256, hash: crypto.SHA256},
		{alg: types.ES384, hash: crypto.SHA384},
		{alg: types.ES512, hash: crypto.SHA512},
	}

	for _, tc := range tcs {
		t.Run(string(tc.alg), func(t *testing.T) {
			hf := tc.hash.HashFunc().New()
			hf.Write([]byte("the message"))
			digest := hf.Sum(nil)

			r, s, err := ecdsa.Sign(rand.Reader, pKey, digest)
			require.NoError(t, err)
			rawsig := r.Bytes()
			rawsig = append(rawsig, s.Bytes()...)

			signFormat := types.Raw
			api.EXPECT().Sign(mock.Anything, okmsId, keyId, &signFormat, tc.alg, true, digest).
				Return(base64.StdEncoding.EncodeToString(rawsig), nil).
				Once()

			sig, err := signer.Sign(rand.Reader, digest, tc.hash)
			require.NoError(t, err)
			require.True(t, ecdsa.VerifyASN1(&pKey.PublicKey, digest, sig))
		})
	}
}
