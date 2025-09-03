package okms

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
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
