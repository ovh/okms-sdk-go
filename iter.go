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

	"github.com/ovh/okms-sdk-go/types"
)

// KeyIter is an iterator for service keys. It helps in iterating efficiently over multiple pages
// without having to deal with the pagination.
type KeyIter struct {
	client   ServiceKeyApi
	pageSize *int32
	state    *types.KeyStates
	buf      *types.ListServiceKeysResponse
	err      error
}

// Next checks if there is another key to return, and advance the cursor if so.
// It returns true if there is another key to get, false otherwise.
// Once the cursor has advanced, the newt key can be retrieved with a call to Value().
func (it *KeyIter) Next(ctx context.Context) bool {
	if it.buf == nil {
		it.buf, it.err = it.client.ListServiceKeys(ctx, nil, it.pageSize, it.state)
		if it.err != nil {
			return true
		}
		return len(*it.buf.ObjectsList) > 0
	}
	if it.buf.ObjectsList != nil && len(*it.buf.ObjectsList) > 1 {
		*it.buf.ObjectsList = (*it.buf.ObjectsList)[1:]
		return true
	}
	if it.buf.IsTruncated != nil && *it.buf.IsTruncated {
		it.buf, it.err = it.client.ListServiceKeys(ctx, it.buf.ContinuationToken, it.pageSize, it.state)
		return it.buf.ObjectsList != nil && len(*it.buf.ObjectsList) > 0
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
	if it.buf.ObjectsList != nil && len(*it.buf.ObjectsList) > 0 {
		val := (*it.buf.ObjectsList)[0]
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
