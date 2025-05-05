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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ovh/okms-sdk-go/internal/utils"
	"github.com/ovh/okms-sdk-go/types"
)

type Major byte

const (
	MajorUndefined Major = iota
	MajorCCM
	MajorSSM
	MajorREST
	MajorKMIP
	MajorDB
	MajorXLIB
)

func (m Major) String() string {
	if s, ok := majorStr[m]; ok {
		return s
	}
	return fmt.Sprintf("Unknown (%d)", m)
}

var majorStr = map[Major]string{
	MajorUndefined: "Undefined",
	MajorCCM:       "CCM",
	MajorSSM:       "SSM",
	MajorREST:      "REST",
	MajorKMIP:      "KMIP",
	MajorDB:        "DB",
	MajorXLIB:      "XLIB",
}

type Minor byte

const (
	MinorGeneral Minor = iota + 1
)

const (
	MinorCCMIAM Minor = iota + 2
	MinorCCMDomain
	MinorCCMDskManager
	MinorCCMSecretManager
	MinorCCMMobManager
	MinorCCMAdminProvider
	MinorCCMAdminAuthProvider
	MinorCCMUserAuthProvider
	MinorCCMSsmProvider
)

const (
	MinorDBFile Minor = iota + 2
	MinorDBS3Provider
	MinorDBNPgSqlProvider
)

const (
	MinorRESTAuthProvider Minor = iota + 2
	MinorRESTServicekeysApi
	MinorRESTSecretsApi
)

const (
	MinorXlibHttpHelper Minor = iota + 2
	MinorXlibIamProvider
	MinorXlibCertProvider
)

func (m Minor) StringFor(major Major) string {
	switch m {
	case 0:
		return "Unspecified"
	case 1:
		return "General"
	}

	if majMap, ok := minorStr[major]; ok {
		if s, ok := majMap[m]; ok {
			return s
		}
	}
	return fmt.Sprintf("Unknown (%d)", m)
}

var minorStr = map[Major]map[Minor]string{
	MajorCCM: {
		MinorCCMIAM:               "IAM",
		MinorCCMDomain:            "Domain",
		MinorCCMDskManager:        "DSK Manager",
		MinorCCMSecretManager:     "Secret Manager",
		MinorCCMMobManager:        "MOB Manager",
		MinorCCMAdminProvider:     "Admin Provider",
		MinorCCMAdminAuthProvider: "Admin Auth Provider",
		MinorCCMUserAuthProvider:  "User Auth provider",
		MinorCCMSsmProvider:       "SSM Provider",
	},
	MajorDB: {
		MinorDBFile:           "File System DB",
		MinorDBS3Provider:     "S3",
		MinorDBNPgSqlProvider: "Postgres",
	},
	MajorREST: {
		MinorRESTAuthProvider:   "Authentication Provider",
		MinorRESTServicekeysApi: "Service Keys API",
		MinorRESTSecretsApi:     "Secrets API",
	},
	MajorXLIB: {
		MinorXlibHttpHelper:   "HTTP Provider",
		MinorXlibIamProvider:  "IAM Provider",
		MinorXlibCertProvider: "Certificate Provider",
	},
	MajorSSM: {},
}

type Category byte

const (
	CategoryUnspecified Category = iota
	CategoryInternal
	CategoryArgument
	CategoryAuthentication
	CategoryAuthorization
	CategoryNotFound
	CategoryDatabase
	CategoryUnavailable
	CategoryBadArgument
)

func (c Category) String() string {
	if s, ok := categoryStr[c]; ok {
		return s
	}
	return fmt.Sprintf("Unknown (%d)", c)
}

var categoryStr = map[Category]string{
	CategoryUnspecified:    "Unspecified",
	CategoryInternal:       "Internal",
	CategoryArgument:       "Argument",
	CategoryAuthentication: "Authentication",
	CategoryAuthorization:  "Authorization",
	CategoryNotFound:       "Not Found",
	CategoryDatabase:       "Database",
	CategoryUnavailable:    "Unavailable",
	CategoryBadArgument:    "Bad Argument",
}

type ErrorCode uint32

func (code ErrorCode) Major() Major {
	return Major((code >> 24) & 0xff)
}

func (code ErrorCode) Minor() Minor {
	return Minor((code >> 16) & 0xff)
}

func (code ErrorCode) Category() Category {
	return Category((code >> 12) & 0x0f)
}

func (code ErrorCode) AppSpecificCode() uint16 {
	//nolint:gosec // No integer overflow possible as we mask it with 0x0fff
	return uint16(code & 0x0fff)
}

func (code ErrorCode) String() string {
	major := code.Major()
	return fmt.Sprintf("Code=%d, System=%s, Component=%s, Category=%s", uint32(code), major, code.Minor().StringFor(major), code.Category())
}

type KmsError struct {
	ErrorCode ErrorCode
	ErrorId   string
	Errors    []error
	RequestId string
}

func NewKmsErrorFromBytes(sbody []byte) *KmsError {
	var errResp types.ErrorResponse
	if e := json.Unmarshal(sbody, &errResp); e == nil {
		return newKmsErrorFromRestResponse(errResp)
	}
	return nil
}

func newKmsErrorFromRestResponse(resp types.ErrorResponse) *KmsError {
	kmsErr := &KmsError{}
	if resp.ErrorId != nil {
		kmsErr.ErrorId = *resp.ErrorId
	}
	if resp.ErrorCode != nil {
		kmsErr.ErrorCode = ErrorCode(utils.ToUint32(*resp.ErrorCode))
	}
	if resp.Errors != nil {
		for _, er := range *resp.Errors {
			kmsErr.Errors = append(kmsErr.Errors, errors.New(er))
		}
	}
	if resp.RequestId != nil {
		kmsErr.RequestId = *resp.RequestId
	}
	return kmsErr
}

func (err *KmsError) Error() string {
	errs := make([]error, 0, len(err.Errors)+1)
	errs = append(errs, err.Errors...)
	errs = append(errs, fmt.Errorf("ID=%q, Request-ID:%q, %s", err.ErrorId, err.RequestId, err.ErrorCode))
	return errors.Join(errs...).Error()
}

func AsKmsError(err error) *KmsError {
	if err != nil {
		var e *KmsError
		if errors.As(err, &e) {
			return e
		}
	}
	return nil
}
