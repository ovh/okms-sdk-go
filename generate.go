// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

package okms

//go:generate mkdir -p types
//go:generate mkdir -p internal
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2 -config .github/codegen/oapi-codegen-types.yaml .github/codegen/schemas/swagger.yaml
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2 -config .github/codegen/oapi-codegen-client.yaml .github/codegen/schemas/swagger.yaml

//#go:generate go run github.com/vektra/mockery/v2@v2.42 --config .github/codegen/mockery.yaml
