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
	"iter"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/types"
)

// ListAllServiceKeys returns an iterator to go through all the keys without having to deal with pagination.
func (client *Client) ListAllServiceKeys(okmsId uuid.UUID, pageSize *uint32, state *types.KeyStates) KeyIter {
	return KeyIter{
		client:   client.API,
		OkmsId:   okmsId,
		pageSize: pageSize,
		buf:      nil,
		state:    state,
	}
}

// KeyIter is an iterator for service keys. It helps in iterating efficiently over multiple pages
// without having to deal with the pagination.
type KeyIter struct {
	OkmsId   uuid.UUID
	client   ServiceKeyApi
	pageSize *uint32
	state    *types.KeyStates
	buf      *types.ListServiceKeysResponse
	err      error
}

// Next checks if there is another key to return, and advance the cursor if so.
// It returns true if there is another key to get, false otherwise.
// Once the cursor has advanced, the next key can be retrieved with a call to Value().
func (it *KeyIter) Next(ctx context.Context) bool {
	if it.err != nil {
		return false
	}
	if it.buf == nil {
		it.buf, it.err = it.client.ListServiceKeys(ctx, it.OkmsId, nil, it.pageSize, it.state)
		if it.err != nil {
			return true
		}
		return len(it.buf.ObjectsList) > 0
	}
	if len(it.buf.ObjectsList) > 1 {
		it.buf.ObjectsList = it.buf.ObjectsList[1:]
		return true
	}
	if it.buf.IsTruncated {
		it.buf, it.err = it.client.ListServiceKeys(ctx, it.OkmsId, &it.buf.ContinuationToken, it.pageSize, it.state)
		return it.err != nil || len(it.buf.ObjectsList) > 0
	}
	return false
}

// Value returns the last key fetched by the iterator after calling Next(), or any error that has occurred internally during the fetch.
//
// Calling Value() multiple times will return the same result unless Next() has been called and has returned true.
func (it *KeyIter) Value() (*types.GetServiceKeyResponse, error) {
	if it.err != nil {
		return nil, it.err
	}
	if len(it.buf.ObjectsList) > 0 {
		val := it.buf.ObjectsList[0]
		return &val, nil
	}
	return nil, nil
}

// Iter returns a go 1.23+ iterator that can be ranged over. The iterator yields 2 values which are
// the key and an error. The key is null if err is not, and err is null if key is not.
func (it KeyIter) Iter(ctx context.Context) iter.Seq2[*types.GetServiceKeyResponse, error] {
	return func(yield func(*types.GetServiceKeyResponse, error) bool) {
		for it.Next(ctx) {
			k, err := it.Value()
			if !yield(k, err) || err != nil {
				return
			}
		}
	}
}

// ListAllSecrets returns an iterator to go through all the secrets without having to deal with pagination.
func (client *Client) ListAllSecrets(okmsId uuid.UUID, pageSize *uint32) SecretIter {
	return SecretIter{
		client:   client.API,
		OkmsId:   okmsId,
		pageSize: pageSize,
		buf:      nil,
	}
}

// SecretIter is an iterator for secrets. It helps in iterating efficiently over multiple pages
// without having to deal with the pagination.
type SecretIter struct {
	OkmsId   uuid.UUID
	client   SecretApiV2
	pageSize *uint32
	buf      *types.ListSecretV2ResponseWithPagination
	err      error
}

// Next checks if there is another secret to return, and advance the cursor if so.
// It returns true if there is another secret to get, false otherwise.
// Once the cursor has advanced, the next secret can be retrieved with a call to Value().
func (it *SecretIter) Next(ctx context.Context) bool {
	if it.err != nil {
		return false
	}
	if it.buf == nil {
		it.buf, it.err = it.client.ListSecretV2(ctx, it.OkmsId, it.pageSize, nil)
		if it.err != nil {
			return true
		}
		return len(it.buf.ListSecretV2Response) > 0
	}
	if len(it.buf.ListSecretV2Response) > 1 {
		it.buf.ListSecretV2Response = (it.buf.ListSecretV2Response)[1:]
		return true
	}

	if it.buf.PageCursorNext != "" {
		it.buf, it.err = it.client.ListSecretV2(ctx, it.OkmsId, it.pageSize, &it.buf.PageCursorNext)
		return it.err != nil || len(it.buf.ListSecretV2Response) > 0
	}
	return false
}

// Value returns the last key fetched by the iterator after calling Next(), or any error that has occurred internally during the fetch.
//
// Calling Value() multiple times will return the same result unless Next() has been called and has returned true.
func (it *SecretIter) Value() (*types.GetSecretV2Response, error) {
	if it.err != nil {
		return nil, it.err
	}
	if len(it.buf.ListSecretV2Response) > 0 {
		val := it.buf.ListSecretV2Response[0]
		return &val, nil
	}
	return nil, nil
}

// Iter returns a go 1.23+ iterator that can be ranged over. The iterator yields 2 values which are
// the secret and an error. The secret is null if err is not, and err is null if secret is not.
func (it SecretIter) Iter(ctx context.Context) iter.Seq2[*types.GetSecretV2Response, error] {
	return func(yield func(*types.GetSecretV2Response, error) bool) {
		for it.Next(ctx) {
			k, err := it.Value()
			if !yield(k, err) || err != nil {
				return
			}
		}
	}
}

// ListAllSecretVersions returns an iterator to go through all the secret versions without having to deal with pagination.
func (client *Client) ListAllSecretVersions(okmsId uuid.UUID, path string, pageSize *uint32) SecretVersionIter {
	return SecretVersionIter{
		client:   client.API,
		OkmsId:   okmsId,
		Path:     path,
		pageSize: pageSize,
		buf:      nil,
	}
}

type SecretVersionIter struct {
	OkmsId   uuid.UUID
	Path     string
	client   SecretApiV2
	pageSize *uint32
	buf      *types.ListSecretVersionV2ResponseWithPagination
	err      error
}

// Next checks if there is another secret version to return, and advance the cursor if so.
// It returns true if there is another secret to get, false otherwise.
// Once the cursor has advanced, the next secret can be retrieved with a call to Value().
func (it *SecretVersionIter) Next(ctx context.Context) bool {
	if it.err != nil {
		return false
	}
	if it.buf == nil {
		it.buf, it.err = it.client.ListSecretVersionV2(ctx, it.OkmsId, it.Path, it.pageSize, nil)
		if it.err != nil {
			return true
		}
		return len(it.buf.ListSecretVersionV2Response) > 0
	}
	if len(it.buf.ListSecretVersionV2Response) > 1 {
		it.buf.ListSecretVersionV2Response = (it.buf.ListSecretVersionV2Response)[1:]
		return true
	}

	if it.buf.PageCursorNext != "" {
		it.buf, it.err = it.client.ListSecretVersionV2(ctx, it.OkmsId, it.Path, it.pageSize, &it.buf.PageCursorNext)
		return it.err != nil || len(it.buf.ListSecretVersionV2Response) > 0
	}
	return false
}

// Value returns the last key fetched by the iterator after calling Next(), or any error that has occurred internally during the fetch.
//
// Calling Value() multiple times will return the same result unless Next() has been called and has returned true.
func (it *SecretVersionIter) Value() (*types.SecretV2Version, error) {
	if it.err != nil {
		return nil, it.err
	}
	if len(it.buf.ListSecretVersionV2Response) > 0 {
		val := it.buf.ListSecretVersionV2Response[0]
		return &val, nil
	}
	return nil, nil
}

// Iter returns a go 1.23+ iterator that can be ranged over. The iterator yields 2 values which are
// the secret version and an error. The secret version is null if err is not, and err is null if secret version is not.
func (it SecretVersionIter) Iter(ctx context.Context) iter.Seq2[*types.SecretV2Version, error] {
	return func(yield func(*types.SecretV2Version, error) bool) {
		for it.Next(ctx) {
			k, err := it.Value()
			if !yield(k, err) || err != nil {
				return
			}
		}
	}
}
