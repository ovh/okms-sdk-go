package okms

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/internal/utils"
	"github.com/ovh/okms-sdk-go/mocks"
	"github.com/ovh/okms-sdk-go/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestKeyIter(t *testing.T) {
	mc := mocks.NewAPIMock(t)
	client := Client{mc}

	okmsId := uuid.New()

	it := client.ListAllServiceKeys(okmsId, nil, nil)

	contToken := "abcdef"
	keys := []types.GetServiceKeyResponse{
		{Name: "a"},
		{Name: "b"},
		{Name: "c"},
		{Name: "d"},
	}

	mc.EXPECT().ListServiceKeys(mock.Anything, okmsId, (*string)(nil), (*uint32)(nil), (*types.KeyStates)(nil)).
		Return(&types.ListServiceKeysResponse{IsTruncated: true, ContinuationToken: contToken, ObjectsList: keys[:2]}, nil).
		Once()

	mc.EXPECT().ListServiceKeys(mock.Anything, okmsId, &contToken, (*uint32)(nil), (*types.KeyStates)(nil)).
		Return(&types.ListServiceKeysResponse{IsTruncated: false, ContinuationToken: "", ObjectsList: keys[2:]}, nil).
		Once()

	i := 0
	for k, err := range it.Iter(context.Background()) {
		require.NoError(t, err)
		require.EqualValues(t, &keys[i], k)
		i++
	}
}

func TestKeyIter_error(t *testing.T) {
	mc := mocks.NewAPIMock(t)
	client := Client{mc}

	okmsId := uuid.New()

	it := client.ListAllServiceKeys(okmsId, nil, nil)

	contToken := "abcdef"
	keys := []types.GetServiceKeyResponse{
		{Name: "a"},
		{Name: "b"},
		{Name: "c"},
		{Name: "d"},
	}

	mc.EXPECT().ListServiceKeys(mock.Anything, okmsId, (*string)(nil), (*uint32)(nil), (*types.KeyStates)(nil)).
		Return(&types.ListServiceKeysResponse{IsTruncated: true, ContinuationToken: contToken, ObjectsList: keys[:2]}, nil).
		Once()

	mc.EXPECT().ListServiceKeys(mock.Anything, okmsId, &contToken, (*uint32)(nil), (*types.KeyStates)(nil)).
		Return(nil, errors.New("Failure")).
		Once()

	i := 0
	for k, err := range it.Iter(context.Background()) {
		if i > 1 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.EqualValues(t, &keys[i], k)
		}
		i++
	}
}

func TestSecretIter(t *testing.T) {
	mc := mocks.NewAPIMock(t)
	client := Client{mc}

	okmsId := uuid.New()

	it := client.ListAllSecrets(okmsId, nil)

	contToken := "abcdef"
	secrets := []types.GetSecretV2Response{
		{Path: utils.StringPtr("a")},
		{Path: utils.StringPtr("b")},
		{Path: utils.StringPtr("c")},
		{Path: utils.StringPtr("d")},
	}

	mc.EXPECT().ListSecretV2(mock.Anything, okmsId, (*uint32)(nil), (*string)(nil)).
		Return(&types.ListSecretV2ResponseWithPagination{ListSecretV2Response: secrets[:2], PageCursorNext: contToken}, nil).
		Once()

	mc.EXPECT().ListSecretV2(mock.Anything, okmsId, (*uint32)(nil), &contToken).
		Return(&types.ListSecretV2ResponseWithPagination{ListSecretV2Response: secrets[2:], PageCursorNext: ""}, nil).
		Once()

	i := 0
	for k, err := range it.Iter(context.Background()) {
		require.NoError(t, err)
		require.EqualValues(t, &secrets[i], k)
		i++
	}
}

func TestSecretIter_error(t *testing.T) {
	mc := mocks.NewAPIMock(t)
	client := Client{mc}

	okmsId := uuid.New()

	it := client.ListAllSecrets(okmsId, nil)

	contToken := "abcdef"
	secrets := []types.GetSecretV2Response{
		{Path: utils.StringPtr("a")},
		{Path: utils.StringPtr("b")},
		{Path: utils.StringPtr("c")},
		{Path: utils.StringPtr("d")},
	}

	mc.EXPECT().ListSecretV2(mock.Anything, okmsId, (*uint32)(nil), (*string)(nil)).
		Return(&types.ListSecretV2ResponseWithPagination{ListSecretV2Response: secrets[:2], PageCursorNext: contToken}, nil).
		Once()

	mc.EXPECT().ListSecretV2(mock.Anything, okmsId, (*uint32)(nil), &contToken).
		Return(nil, errors.New("Failure")).
		Once()

	i := 0
	for k, err := range it.Iter(context.Background()) {
		if i > 1 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.EqualValues(t, &secrets[i], k)
		}
		i++
	}
}

func TestSecretVersionIter(t *testing.T) {
	mc := mocks.NewAPIMock(t)
	client := Client{mc}

	okmsId := uuid.New()

	it := client.ListAllSecretVersions(okmsId, "test", nil)

	contToken := "abcdef"
	secretVersions := []types.SecretV2Version{
		{Id: 1},
		{Id: 2},
		{Id: 3},
		{Id: 4},
	}

	mc.EXPECT().ListSecretVersionV2(mock.Anything, okmsId, "test", (*uint32)(nil), (*string)(nil)).
		Return(&types.ListSecretVersionV2ResponseWithPagination{ListSecretVersionV2Response: secretVersions[:2], PageCursorNext: contToken}, nil).
		Once()

	mc.EXPECT().ListSecretVersionV2(mock.Anything, okmsId, "test", (*uint32)(nil), &contToken).
		Return(&types.ListSecretVersionV2ResponseWithPagination{ListSecretVersionV2Response: secretVersions[2:], PageCursorNext: ""}, nil).
		Once()

	i := 0
	for k, err := range it.Iter(context.Background()) {
		require.NoError(t, err)
		require.EqualValues(t, &secretVersions[i], k)
		i++
	}
}

func TestSecretVersionIter_error(t *testing.T) {
	mc := mocks.NewAPIMock(t)
	client := Client{mc}

	okmsId := uuid.New()

	it := client.ListAllSecretVersions(okmsId, "test", nil)

	contToken := "abcdef"
	secretVersions := []types.SecretV2Version{
		{Id: 1},
		{Id: 2},
		{Id: 3},
		{Id: 4},
	}

	mc.EXPECT().ListSecretVersionV2(mock.Anything, okmsId, "test", (*uint32)(nil), (*string)(nil)).
		Return(&types.ListSecretVersionV2ResponseWithPagination{ListSecretVersionV2Response: secretVersions[:2], PageCursorNext: contToken}, nil).
		Once()

	mc.EXPECT().ListSecretVersionV2(mock.Anything, okmsId, "test", (*uint32)(nil), &contToken).
		Return(nil, errors.New("Failure")).
		Once()

	i := 0
	for k, err := range it.Iter(context.Background()) {
		if i > 1 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.EqualValues(t, &secretVersions[i], k)
		}
		i++
	}
}
