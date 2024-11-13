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
	"strconv"
	"testing"
)

func TestErrorParsing(t *testing.T) {
	testcases := []struct {
		code     ErrorCode
		major    Major
		minor    Minor
		category Category
	}{
		{16846849, MajorCCM, MinorGeneral, CategoryInternal},
		{16850946, MajorCCM, MinorGeneral, CategoryArgument},
		{16912385, MajorCCM, MinorCCMIAM, CategoryInternal},
		{16916481, MajorCCM, MinorCCMIAM, CategoryArgument},
		{16920577, MajorCCM, MinorCCMIAM, CategoryAuthentication},
		{16924673, MajorCCM, MinorCCMIAM, CategoryAuthorization},
		{16994305, MajorCCM, MinorCCMDomain, CategoryNotFound},
		{17043458, MajorCCM, MinorCCMDskManager, CategoryInternal},
		{17125377, MajorCCM, MinorCCMSecretManager, CategoryNotFound},
		{17174530, MajorCCM, MinorCCMMobManager, CategoryInternal},
		{17178625, MajorCCM, MinorCCMMobManager, CategoryArgument},
		{17190913, MajorCCM, MinorCCMMobManager, CategoryNotFound},

		{33624065, MajorSSM, MinorGeneral, CategoryInternal},
		{33628161, MajorSSM, MinorGeneral, CategoryArgument},

		{50401281, MajorREST, MinorGeneral, CategoryInternal},
		{50425858, MajorREST, MinorGeneral, CategoryUnavailable},
		{50405377, MajorREST, MinorGeneral, CategoryArgument},
		{50475011, MajorREST, MinorRESTAuthProvider, CategoryAuthentication},

		{100732929, MajorXLIB, MinorGeneral, CategoryInternal},
		{100798465, MajorXLIB, MinorXlibHttpHelper, CategoryInternal},
		{100864001, MajorXLIB, MinorXlibIamProvider, CategoryInternal},
		{100929537, MajorXLIB, MinorXlibCertProvider, CategoryInternal},
		{100954113, MajorXLIB, MinorXlibCertProvider, CategoryUnavailable},
	}

	for _, tc := range testcases {
		t.Run(strconv.Itoa(int(tc.code)), func(t *testing.T) {
			if tc.major != tc.code.Major() {
				t.Errorf("Invalid Major. Wants %d, got %d", tc.major, tc.code.Major())
			}
			if tc.minor != tc.code.Minor() {
				t.Errorf("Invalid Minor. Wants %d, got %d", tc.minor, tc.code.Minor())
			}
			if tc.category != tc.code.Category() {
				t.Errorf("Invalid category. Wants %d, got %d", tc.category, tc.code.Category())
			}
		})
	}
}

func TestErrorString(t *testing.T) {
	code := ErrorCode(16846849)
	if code.String() != "Code=16846849, System=CCM, Component=General, Category=Internal" {
		t.Errorf("Invalid string value")
	}
}
