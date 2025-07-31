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

type ListSecretV2ResponseWithHeaders struct {
	Body    ListSecretV2Response
	Headers ListSecretV2ResponseHeaders
}

type ListSecretV2ResponseHeaders struct {
	XPaginationCursorNext string
}

type ListSecretVersionV2ResponseWithHeaders struct {
	Body    ListSecretVersionV2Response
	Headers ListSecretVersionV2ResponseHeaders
}

type ListSecretVersionV2ResponseHeaders struct {
	XPaginationCursorNext string
}
