package okms

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestDataKeyProvider_GenerateDataKey(t *testing.T) {
	api := mocks.NewAPIMock(t)
	client := Client{api}
	plainKey := []byte("the-plain-key")
	cipherKey := "the-encrypted-key"

	okmsId := uuid.New()
	keyId := uuid.New()
	keyName := "foo"
	keySize := 256

	api.EXPECT().GenerateDataKey(mock.Anything, okmsId, keyId, keyName, int32(keySize)).
		Return(plainKey, cipherKey, nil).
		Once()

	dk := client.DataKeys(okmsId, keyId)

	plain, encr, err := dk.GenerateDataKey(context.Background(), keyName, keySize)

	require.NoError(t, err)
	require.Equal(t, plainKey, plain)
	require.Equal(t, []byte(cipherKey), encr)

	_, _, err = dk.GenerateDataKey(context.Background(), keyName, -12)
	require.Error(t, err)

	api.EXPECT().GenerateDataKey(mock.Anything, okmsId, keyId, keyName, int32(keySize)).
		Return(nil, "", errors.New("failed")).
		Once()
	_, _, err = dk.GenerateDataKey(context.Background(), keyName, keySize)
	require.Error(t, err)
}

func TestDataKeyProvider_DecryptDataKey(t *testing.T) {
	api := mocks.NewAPIMock(t)
	client := Client{api}
	plainKey := []byte("the-plain-key")
	cipherKey := "the-encrypted-key"

	okmsId := uuid.New()
	keyId := uuid.New()

	api.EXPECT().DecryptDataKey(mock.Anything, okmsId, keyId, cipherKey).
		Return(plainKey, nil).
		Once()

	dk := client.DataKeys(okmsId, keyId)

	plain, err := dk.DecryptDataKey(context.Background(), []byte(cipherKey))

	require.NoError(t, err)
	require.Equal(t, plainKey, plain)

	api.EXPECT().DecryptDataKey(mock.Anything, okmsId, keyId, cipherKey).
		Return(nil, errors.New("failed")).
		Once()

	_, err = dk.DecryptDataKey(context.Background(), []byte(cipherKey))
	require.Error(t, err)
}

func TestDataKeyProvider_Encrypt_DecryptGCM(t *testing.T) {
	api := mocks.NewAPIMock(t)
	client := Client{api}
	plainKey := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	cipherKey := "the-encrypted-key"
	data := []byte("Hello World")
	aad := []byte("AAD")

	okmsId := uuid.New()
	keyId := uuid.New()
	keyName := "foo"
	keySize := 256

	api.EXPECT().GenerateDataKey(mock.Anything, okmsId, keyId, keyName, int32(keySize)).
		Return(plainKey, cipherKey, nil).
		Once()
	api.EXPECT().DecryptDataKey(mock.Anything, okmsId, keyId, cipherKey).
		Return(plainKey, nil).
		Once()

	dk := client.DataKeys(okmsId, keyId)

	cipherText, encrKey, nonce, err := dk.EncryptGCM(context.Background(), keyName, data, aad)
	require.NoError(t, err)

	plainData, err := dk.DecryptGCM(context.Background(), encrKey, cipherText, nonce, aad)
	require.NoError(t, err)
	require.Equal(t, data, plainData)
}
