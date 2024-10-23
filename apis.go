// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under
// the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
// ANY KIND, either express or implied. See the License for the specific language
// governing permissions and limitations under the License.

// Package okms is a client for interacting with OVHcloud KMS REST-API.
package okms

import (
	"context"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/types"
)

var _ API = (*Client)(nil)

// API is the interface abstracting the KMS clients methods.
type API interface {
	// RandomApi
	DataKeyApi
	SignatureApi
	EncryptionApi
	ServiceKeyApi
	// SecretApi
	// Ping(ctx context.Context) error
	SetCustomHeader(key, value string)
}

// type RandomApi interface {
// 	GenerateRandomBytes(ctx context.Context, length int) (*types.GetRandomResponse, error)
// }

// DataKeyApi is the client interface used to create and retrieve KMS data keys using a remote symmetric key.
type DataKeyApi interface {
	// GenerateDataKey creates a new data key of the given size, protected by the service key with the ID `keyId`.
	// It returns the plain datakey, and the JWE encrypted version of it, which can be decrypted by calling the DecryptDataKey method.
	GenerateDataKey(ctx context.Context, keyId uuid.UUID, name string, size int32) (plain []byte, encrypted string, err error)
	// DecryptDataKey decrypts a JWE encrypted data key protected by the service key with the ID `keyId`.
	DecryptDataKey(ctx context.Context, keyId uuid.UUID, encryptedKey string) ([]byte, error)
}

// SignatureApi is the client interface used to sign data and verify signatures using a remote asymmetric key-pair.
type SignatureApi interface {
	// Sign signs the given message with the remote private key having the ID `keyId`. The message can be pre-hashed or not.
	Sign(ctx context.Context, keyId uuid.UUID, alg types.DigitalSignatureAlgorithms, preHashed bool, msg []byte) (string, error)
	// Verify checks the signature of given message against the remote public key having the ID `keyId`. The message can be pre-hashed or not.
	Verify(ctx context.Context, keyId uuid.UUID, alg types.DigitalSignatureAlgorithms, preHashed bool, msg []byte, sig string) (bool, error)
}

// EncryptionApi is the client interface used to encrypt and decrypt data using a remote symmetric key.
type EncryptionApi interface {
	// Encrypt encrypts `data` with the remote symmetric key having the ID `keyId`. Returns a JWE (Json Web Encryption) string.
	Encrypt(ctx context.Context, keyId uuid.UUID, keyCtx string, data []byte) (string, error)
	// Decrypt decrypts JWE `data` previously encrypted with the remote symmetric key having the ID `keyId`.
	Decrypt(ctx context.Context, keyId uuid.UUID, keyCtx, data string) ([]byte, error)
}

// ServiceKeyApi is the client interface used to query and manipulate the remote service keys lifecycle.
type ServiceKeyApi interface {
	// ActivateServiceKey activates or re-activates a service key.
	ActivateServiceKey(ctx context.Context, keyId uuid.UUID) error
	// DeactivateServiceKey deactivates a service key with the given deactivation reason.
	DeactivateServiceKey(ctx context.Context, keyId uuid.UUID, reason types.RevocationReasons) error
	// CreateImportServiceKey is used to either generate a new key securely in the KMS, or to import a plain key into the KMS domain.
	CreateImportServiceKey(ctx context.Context, format *types.KeyFormats, body types.CreateImportServiceKeyRequest) (*types.GetServiceKeyResponse, error)
	// DeleteServiceKey deletes a deactivated service key. The key cannot be recovered after deletion.
	// It will fail if the key is not deactivated.
	DeleteServiceKey(ctx context.Context, keyId uuid.UUID) error
	// GetServiceKey returns a key metadata. If format is not nil, then the public key material is also returned.
	GetServiceKey(ctx context.Context, keyId uuid.UUID, format *types.KeyFormats) (*types.GetServiceKeyResponse, error)
	// ListServiceKeys returns a page of service keys. The response contains a continuationToken that must be passed to the
	// subsequent calls in order to get the next page. The state parameter when no nil is used to query keys having a specific state.
	ListServiceKeys(ctx context.Context, continuationToken *string, maxKey *int32, state *types.KeyStates) (*types.ListServiceKeysResponse, error)
	// UpdateServiceKey updates some service key metadata.
	UpdateServiceKey(ctx context.Context, keyId uuid.UUID, body types.PatchServiceKeyRequest) (*types.GetServiceKeyResponse, error)
}

// type SecretApi interface {
// 	GetSecretsMetadata(ctx context.Context, path string, list bool) (*types.GetMetadataResponse, error)
// 	PatchSecretMetadata(ctx context.Context, path string, body types.SecretUpdatableMetadata) error
// 	DeleteSecretMetadata(ctx context.Context, path string) error
// 	PostSecretMetadata(ctx context.Context, path string, body types.SecretUpdatableMetadata) error

// 	GetSecretConfig(ctx context.Context) (*types.GetConfigResponse, error)
// 	PostSecretConfig(ctx context.Context, body types.PostConfigRequest) error

// 	GetSecretRequest(ctx context.Context, path string, version *int32) (*types.GetSecretResponse, error)
// 	GetSecretSubkeys(ctx context.Context, path string, depth, version *int32) (*types.GetSecretSubkeysResponse, error)
// 	PostSecretRequest(ctx context.Context, path string, body types.PostSecretRequest) (*types.PostSecretResponse, error)
// 	PatchSecretRequest(ctx context.Context, path string, body types.PostSecretRequest) (*types.PatchSecretResponse, error)
// 	DeleteSecretRequest(ctx context.Context, path string) error
// 	DeleteSecretVersions(ctx context.Context, path string, versions []int32) error
// 	PostSecretDestroy(ctx context.Context, path string, versions []int32) error
// 	PostSecretUndelete(ctx context.Context, path string, versions []int32) error
// }
