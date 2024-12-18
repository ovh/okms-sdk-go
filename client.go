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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/ovh/okms-sdk-go/internal"
	"github.com/ovh/okms-sdk-go/types"
	"golang.org/x/crypto/ssh"
)

const DefaultHTTPClientTimeout = 30 * time.Second

type Client struct {
	API
}

// WithCustomHeader adds additional HTTP headers that will be sent with every outgoing requests.
func (client *Client) WithCustomHeader(key, value string) *Client {
	client.SetCustomHeader(key, value)
	return client
}

// GenerateSymmetricKey asks the KMS to generate a symmetric key with the given bits length, name and usage. The keyCtx parameter can be left empty if not needed.
func (client *Client) GenerateSymmetricKey(ctx context.Context, bitSize types.KeySizes, name, keyCtx string, ops ...types.CryptographicUsages) (*types.GetServiceKeyResponse, error) {
	var keyContext *string
	if keyCtx != "" {
		keyContext = &keyCtx
	}
	kTy := types.Oct
	body := types.CreateImportServiceKeyRequest{
		Context:    keyContext,
		Name:       name,
		Type:       &kTy,
		Operations: &ops,
		Size:       &bitSize,
		Keys:       nil,
	}
	return client.CreateImportServiceKey(ctx, nil, body)
}

// GenerateRSAKeyPair asks the KMS to generate an RSA asymmetric key-pair with the given bits length, name and usage. The keyCtx parameter can be left empty if not needed.
func (client *Client) GenerateRSAKeyPair(ctx context.Context, bitSize types.KeySizes, name, keyCtx string, ops ...types.CryptographicUsages) (*types.GetServiceKeyResponse, error) {
	var keyContext *string
	if keyCtx != "" {
		keyContext = &keyCtx
	}
	kTy := types.RSA
	body := types.CreateImportServiceKeyRequest{
		Context:    keyContext,
		Name:       name,
		Type:       &kTy,
		Operations: &ops,
		Size:       &bitSize,
		Keys:       nil,
	}
	return client.CreateImportServiceKey(ctx, nil, body)
}

// GenerateECKeyPair asks the KMS to generate an EC asymmetric key-pair with the given elliptic curve, name and usage. The keyCtx parameter can be left empty if not needed.
func (client *Client) GenerateECKeyPair(ctx context.Context, curve types.Curves, name, keyCtx string, ops ...types.CryptographicUsages) (*types.GetServiceKeyResponse, error) {
	var keyContext *string
	if keyCtx != "" {
		keyContext = &keyCtx
	}
	kTy := types.EC
	body := types.CreateImportServiceKeyRequest{
		Context:    keyContext,
		Name:       name,
		Type:       &kTy,
		Operations: &ops,
		Curve:      &curve,
		Keys:       nil,
	}
	return client.CreateImportServiceKey(ctx, nil, body)
}

func (client *Client) importJWK(ctx context.Context, jwk types.JsonWebKeyRequest, name, keyCtx string, ops ...types.CryptographicUsages) (*types.GetServiceKeyResponse, error) {
	var keyContext *string
	if keyCtx != "" {
		keyContext = &keyCtx
	}
	req := types.CreateImportServiceKeyRequest{
		Context:    keyContext,
		Name:       name,
		Operations: &ops,
		Keys:       &[]types.JsonWebKeyRequest{jwk},
	}
	format := types.Jwk
	return client.CreateImportServiceKey(ctx, &format, req)
}

// ImportKey imports a key into the KMS. keyCtx can be left empty if not needed.
//
// The accepted types of the key parameter are
//   - *rsa.PrivateKey
//   - *ecdsa.PrivateKey
//   - types.JsonWebKey and *types.JsonWebKey
//   - []byte for importing symmetric keys.
func (client *Client) ImportKey(ctx context.Context, key any, name, keyCtx string, ops ...types.CryptographicUsages) (*types.GetServiceKeyResponse, error) {
	switch k := key.(type) {
	case types.JsonWebKeyRequest:
		return client.importJWK(ctx, k, name, keyCtx, ops...)
	case *types.JsonWebKeyRequest:
		return client.importJWK(ctx, *k, name, keyCtx, ops...)
	}
	jwk, err := types.NewJsonWebKey(key, ops, name)
	if err != nil {
		return nil, err
	}
	jwkRequest := types.JsonWebKeyRequest{
		Kid:    &jwk.Kid,
		KeyOps: jwk.KeyOps,
		Kty:    jwk.Kty,
		D:      jwk.D,
		E:      jwk.E,
		N:      jwk.N,
		P:      jwk.P,
		Q:      jwk.Q,
		Dp:     jwk.Dp,
		Dq:     jwk.Dq,
		Qi:     jwk.Qi,
		X:      jwk.X,
		Y:      jwk.Y,
		Crv:    jwk.Crv,
		K:      jwk.K,
	}
	return client.importJWK(ctx, jwkRequest, name, keyCtx, ops...)
}

// ImportKeyPairPEM imports a PEM formated key into the KMS. keyCtx can be left empty if not needed.
//
// Supported PEM types are:
//   - PKCS8
//   - PKCS1 private keys
//   - SEC1
//   - OpenSSH private keys
func (client *Client) ImportKeyPairPEM(ctx context.Context, privateKeyPem []byte, name, keyCtx string, ops ...types.CryptographicUsages) (*types.GetServiceKeyResponse, error) {
	block, _ := pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("No key to import")
	}
	var k any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		k, err = ssh.ParseRawPrivateKey(privateKeyPem)
	default:
		return nil, fmt.Errorf("Unsupported PEM type: %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	return client.ImportKey(ctx, k, name, keyCtx, ops...)
}

// ExportJwkPublicKey returns the public part of a key pair as a Json Web Key.
func (client *Client) ExportJwkPublicKey(ctx context.Context, keyID uuid.UUID) (*types.JsonWebKeyResponse, error) {
	format := types.Jwk
	k, err := client.GetServiceKey(ctx, keyID, &format)
	if err != nil {
		return nil, err
	}
	if k.Attributes != nil && (*k.Attributes)["state"] != "active" {
		return nil, fmt.Errorf("The key is not active (state is %q)", (*k.Attributes)["state"])
	}
	if k.Keys == nil || len(*k.Keys) == 0 {
		return nil, errors.New("The server returned no public key")
	}
	return &(*k.Keys)[0], nil
}

// ExportPublicKey returns the public part of a key pair as a [crypto.PublicKey].
//
// The returned key can then be cast into *rsa.PublicKey or *ecdsa.PublicKey.
func (client *Client) ExportPublicKey(ctx context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
	k, err := client.ExportJwkPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return k.PublicKey()
}

// apiClient is the main implementation of KMS rest api http client.
type apiClient struct {
	inner         internal.ClientWithResponsesInterface
	customHeaders map[string]string
}

// LeveledLogger represents loggers that can be used inside the client.
type LeveledLogger retryablehttp.LeveledLogger

// ClientConfig is used to configure Rest clients created using NewRestAPIClient().
type ClientConfig struct {
	Timeout    *time.Duration
	Retry      *RetryConfig
	Logger     LeveledLogger
	TlsCfg     *tls.Config
	Middleware func(http.RoundTripper) http.RoundTripper
}

type RetryConfig struct {
	RetryMax     int
	RetryWaitMin time.Duration
	RetryWaitMax time.Duration
}

type debugTransport struct {
	next http.RoundTripper
	out  io.Writer
}

// RoundTrip implements http.RoundTripper.
func (t *debugTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	data, _ := httputil.DumpRequestOut(r, true)
	fmt.Fprintf(os.Stderr, "REQUEST:\n%s\n", data)
	resp, err := t.next.RoundTrip(r)
	if err != nil {
		return resp, err
	}
	data, _ = httputil.DumpResponse(resp, true)
	fmt.Fprintf(os.Stderr, "RESPONSE:\n%s\n", data)
	return resp, nil
}

// DebugTransport creates an http client middleware that will dump all the HTTP resquests and
// responses to the giver io.Writer. It can be passed to ClientConfig.Middleware.
func DebugTransport(out io.Writer) func(http.RoundTripper) http.RoundTripper {
	return func(rt http.RoundTripper) http.RoundTripper {
		if rt == nil {
			rt = http.DefaultTransport
		}
		if out == nil {
			out = os.Stderr
		}
		return &debugTransport{
			next: rt,
			out:  out,
		}
	}
}

// NewRestAPIClient creates and initializes a new HTTP connection to the KMS at url `endpoint`
// using the provided client configuration. It allows configuring retries, timeouts and loggers.
func NewRestAPIClient(endpoint string, clientCfg ClientConfig) (*Client, error) {
	client := retryablehttp.NewClient()
	client.HTTPClient.Timeout = DefaultHTTPClientTimeout
	client.Logger = nil

	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig = clientCfg.TlsCfg
	if clientCfg.Logger != nil {
		client.Logger = clientCfg.Logger
	}

	if clientCfg.Timeout != nil {
		client.HTTPClient.Timeout = *clientCfg.Timeout
	}

	if clientCfg.Retry != nil {
		client.RetryMax = clientCfg.Retry.RetryMax
		if clientCfg.Retry.RetryWaitMin > 0 {
			client.RetryWaitMin = clientCfg.Retry.RetryWaitMin
		}
		if clientCfg.Retry.RetryWaitMax > 0 {
			client.RetryWaitMax = clientCfg.Retry.RetryWaitMax
		}
	}
	if clientCfg.Middleware != nil {
		client.HTTPClient.Transport = clientCfg.Middleware(client.HTTPClient.Transport)
	}

	client.ErrorHandler = retryablehttp.PassthroughErrorHandler

	return NewRestAPIClientWithHttp(endpoint, client.StandardClient())
}

// NewRestAPIClientWithHttp is a lower level constructor to create and initialize a new HTTP
// connection to the KMS at url `endpoint` using the provided [http.Client].
//
// The client must be configured with an appropriate tls.Config using client TLS certificates for authentication.
func NewRestAPIClientWithHttp(endpoint string, c *http.Client) (*Client, error) {
	restClient := &apiClient{}
	baseUrl := strings.TrimRight(endpoint, "/")
	client, err := internal.NewClientWithResponses(baseUrl, internal.WithHTTPClient(c), internal.WithRequestEditorFn(restClient.addRequestHeaders))

	if err != nil {
		return nil, fmt.Errorf("Failed to initialize KMS REST client: %w", err)
	}
	restClient.inner = client
	return &Client{restClient}, nil
}

// InternalHttpClient is the low level, internal http client generated by oapi-codegen.
// It may be used as an escape hatch to some low level features. Use at your own risk.
type InternalHttpClient = internal.Client

// GetInternalClient returns the internal client wrapped.
// It is an escape hatch to some low level features. Use at your own risk.
func (client *apiClient) GetInternalClient() *InternalHttpClient {
	c := client.inner.(*internal.ClientWithResponses)
	return c.ClientInterface.(*internal.Client)
}

func (client *apiClient) SetCustomHeader(key, value string) {
	if client.customHeaders == nil {
		client.customHeaders = make(map[string]string)
	}
	client.customHeaders[key] = value
}

func (client *apiClient) addRequestHeaders(ctx context.Context, req *http.Request) error {
	for k, v := range client.customHeaders {
		req.Header.Set(k, v)
	}
	if ctxHdrs := getContextHeaders(ctx); ctxHdrs != nil {
		for k, v := range ctxHdrs {
			req.Header.Set(k, v)
		}
	}
	return nil
}

// func (client *apiClient) Ping(ctx context.Context) error {
// 	_, err := client.GenerateRandomBytes(ctx, 1)
// 	return err
// }

// func (client *apiClient) GenerateRandomBytes(ctx context.Context, length int) (*types.GetRandomResponse, error) {
// 	l := int32(length)
// 	r, err := mapRestErr(client.inner.GenerateRandomBytesWithResponse(ctx, &types.GenerateRandomBytesParams{Length: &l}))
// 	if err != nil {
// 		return nil, err
// 	}
// 	return r.JSON200, err
// }

// GetServiceKey returns a key metadata. If format is not nil, then the public key material is also returned.
func (client *apiClient) GetServiceKey(ctx context.Context, keyId uuid.UUID, format *types.KeyFormats) (*types.GetServiceKeyResponse, error) {
	params := &types.GetServiceKeyParams{Format: format}
	r, err := mapRestErr(client.inner.GetServiceKeyWithResponse(ctx, keyId, params))
	if err != nil {
		return nil, err
	}
	return r.JSON200, err
}

// ListServiceKeys returns a page of service keys. The response contains a continuationToken that must be passed to the
// subsequent calls in order to get the next page. The state parameter when no nil is used to query keys having a specific state.
func (client *apiClient) ListServiceKeys(ctx context.Context, continuationToken *string, maxKeys *int32, state *types.KeyStates) (*types.ListServiceKeysResponse, error) {
	params := &types.ListServiceKeysParams{ContinuationToken: continuationToken, Max: maxKeys, State: state}
	r, err := mapRestErr(client.inner.ListServiceKeysWithResponse(ctx, params))
	if err != nil {
		return nil, err
	}
	return r.JSON200, err
}

// ActivateServiceKey activates or re-activates a service key.
func (client *apiClient) ActivateServiceKey(ctx context.Context, keyId uuid.UUID) error {
	_, err := mapRestErr(client.inner.ActivateServiceKeyWithResponse(ctx, keyId))
	return err
}

// UpdateServiceKey updates some service key metadata.
func (client *apiClient) UpdateServiceKey(ctx context.Context, keyId uuid.UUID, body types.PatchServiceKeyRequest) (*types.GetServiceKeyResponse, error) {
	r, err := mapRestErr(client.inner.PatchServiceKeyWithResponse(ctx, keyId, body))
	if err != nil {
		return nil, err
	}
	return r.JSON200, err
}

// CreateImportServiceKey is the low level API used to either generate a new key securely in the KMS, or to import a plain key into the KMS domain.
func (client *apiClient) CreateImportServiceKey(ctx context.Context, format *types.KeyFormats, body types.CreateImportServiceKeyRequest) (*types.GetServiceKeyResponse, error) {
	r, err := mapRestErr(client.inner.CreateImportServiceKeyWithResponse(ctx, &types.CreateImportServiceKeyParams{Format: format}, body))
	if err != nil {
		return nil, err
	}
	return r.JSON201, err
}

// DeactivateServiceKey deactivates a service key with the given deactivation reason.
func (client *apiClient) DeactivateServiceKey(ctx context.Context, keyId uuid.UUID, reason types.RevocationReasons) error {
	_, err := mapRestErr(client.inner.DeactivateServiceKeyWithResponse(ctx, keyId, types.DeactivateServicekeyRequest{Reason: reason}))
	return err
}

// DeleteServiceKey deletes a deactivated service key. The key cannot be recovered after deletion.
// It will fail if the key is not deactivated.
func (client *apiClient) DeleteServiceKey(ctx context.Context, keyId uuid.UUID) error {
	_, err := mapRestErr(client.inner.DeleteServiceKeyWithResponse(ctx, keyId))
	return err
}

// DecryptDataKey decrypts a JWE encrypted data key protected by the service key with the ID `keyId`.
func (client *apiClient) DecryptDataKey(ctx context.Context, keyId uuid.UUID, encryptedKey string) ([]byte, error) {
	r, err := mapRestErr(client.inner.DecryptDataKeyWithResponse(ctx, keyId, types.DecryptDataKeyRequest{Key: encryptedKey}))
	if err != nil {
		return nil, err
	}
	if len(r.JSON200.Plaintext) == 0 {
		return nil, errors.New("Server returned no key")
	}
	return r.JSON200.Plaintext, nil
}

// GenerateDataKey creates a new data key of the given size, protected by the service key with the ID `keyId`.
// It returns the plain datakey, and the JWE encrypted version of it, which can be decrypted by calling the DecryptDataKey method.
func (client *apiClient) GenerateDataKey(ctx context.Context, keyId uuid.UUID, name string, size int32) (plain []byte, encrypted string, err error) {
	req := types.GenerateDataKeyRequest{Size: size}
	if name != "" {
		req.Name = &name
	}
	r, err := mapRestErr(client.inner.GenerateDataKeyWithResponse(ctx, keyId, req))
	if err != nil {
		return nil, "", err
	}
	if r.JSON201.Plaintext == nil || len(*r.JSON201.Plaintext) == 0 {
		return nil, "", errors.New("Server returned no key")
	}
	return *r.JSON201.Plaintext, r.JSON201.Key, nil
}

// Decrypt decrypts JWE `data` previously encrypted with the remote symmetric key having the ID `keyId`.
func (client *apiClient) Decrypt(ctx context.Context, keyId uuid.UUID, keyCtx, data string) ([]byte, error) {
	req := types.DecryptRequest{Ciphertext: data}
	if keyCtx != "" {
		req.Context = &keyCtx
	}
	r, err := mapRestErr(client.inner.DecryptWithResponse(ctx, keyId, req))
	if err != nil {
		return nil, err
	}
	return r.JSON200.Plaintext, nil
}

// Encrypt encrypts `data` with the remote symmetric key having the ID `keyId`. Returns a JWE (Json Web Encryption) string.
func (client *apiClient) Encrypt(ctx context.Context, keyId uuid.UUID, keyCtx string, data []byte) (string, error) {
	req := types.EncryptRequest{Plaintext: data}
	if keyCtx != "" {
		req.Context = &keyCtx
	}
	r, err := mapRestErr(client.inner.EncryptWithResponse(ctx, keyId, req))
	if err != nil {
		return "", err
	}
	return r.JSON200.Ciphertext, nil
}

// Sign signs the given message with the remote private key having the ID `keyId`. The message can be pre-hashed or not.
func (client *apiClient) Sign(ctx context.Context, keyId uuid.UUID, format *types.SignatureFormats, alg types.DigitalSignatureAlgorithms, preHashed bool, msg []byte) (string, error) {
	req := types.SignRequest{
		Alg:      alg,
		Isdigest: &preHashed,
		Message:  msg,
	}
	param := &types.SignParams{
		Format: format,
	}
	r, err := mapRestErr(client.inner.SignWithResponse(ctx, keyId, param, req))
	if err != nil {
		return "", err
	}
	if r.JSON200.Signature == "" {
		return "", errors.New("Server returned no signature")
	}
	return r.JSON200.Signature, err
}

// Verify checks the signature of given message against the remote public key having the ID `keyId`. The message can be pre-hashed or not.
func (client *apiClient) Verify(ctx context.Context, keyId uuid.UUID, alg types.DigitalSignatureAlgorithms, preHashed bool, msg []byte, sig string) (bool, error) {
	req := types.VerifyRequest{
		Alg:       &alg,
		Isdigest:  &preHashed,
		Message:   &msg,
		Signature: sig,
	}
	r, err := mapRestErr(client.inner.VerifyWithResponse(ctx, keyId, req))
	if err != nil {
		return false, err
	}
	return r.JSON200.Result, nil
}

// func (client *apiClient) DeleteSecretMetadata(ctx context.Context, path string) error {
// 	_, err := mapRestErr(client.inner.DeleteSecretMetadataWithResponse(ctx, path))
// 	return err
// }

// func (client *apiClient) DeleteSecretRequest(ctx context.Context, path string) error {
// 	_, err := mapRestErr(client.inner.DeleteSecretRequestWithResponse(ctx, path))
// 	return err
// }

// func (client *apiClient) DeleteSecretVersions(ctx context.Context, path string, versions []int32) error {
// 	_, err := mapRestErr(client.inner.DeleteSecretVersionsWithResponse(ctx, path, types.SecretVersionsRequest{Versions: versions}))
// 	return err
// }

// func (client *apiClient) GetSecretConfig(ctx context.Context) (*types.GetConfigResponse, error) {
// 	r, err := mapRestErr(client.inner.GetSecretConfigWithResponse(ctx))
// 	if err != nil {
// 		return nil, err
// 	}
// 	return r.JSON200, err
// }

// func (client *apiClient) GetSecretRequest(ctx context.Context, path string, version *int32) (*types.GetSecretResponse, error) {
// 	r, err := mapRestErr(client.inner.GetSecretRequestWithResponse(ctx, path, &types.GetSecretRequestParams{Version: version}))
// 	if err != nil {
// 		return nil, err
// 	}
// 	return r.JSON200, err
// }

// func (client *apiClient) GetSecretSubkeys(ctx context.Context, path string, depth, version *int32) (*types.GetSecretSubkeysResponse, error) {
// 	r, err := mapRestErr(client.inner.GetSecretSubkeysWithResponse(ctx, path, &types.GetSecretSubkeysParams{Depth: depth, Version: version}))
// 	if err != nil {
// 		return nil, err
// 	}
// 	return r.JSON200, err
// }

// func (client *apiClient) GetSecretsMetadata(ctx context.Context, path string, list bool) (*types.GetMetadataResponse, error) {
// 	r, err := mapRestErr(client.inner.GetSecretsMetadataWithResponse(ctx, path, &types.GetSecretsMetadataParams{List: &list}))
// 	if err != nil {
// 		return nil, err
// 	}
// 	return r.JSON200, err
// }

// func (client *apiClient) PatchSecretMetadata(ctx context.Context, path string, body types.SecretUpdatableMetadata) error {
// 	_, err := mapRestErr(client.inner.PatchSecretMetadataWithResponse(ctx, path, body))
// 	return err
// }

// func (client *apiClient) PatchSecretRequest(ctx context.Context, path string, body types.PostSecretRequest) (*types.PatchSecretResponse, error) {
// 	r, err := mapRestErr(client.inner.PatchSecretRequestWithResponse(ctx, path, body))
// 	if err != nil {
// 		return nil, err
// 	}
// 	return r.JSON200, err
// }

// func (client *apiClient) PostSecretConfig(ctx context.Context, body types.PostConfigRequest) error {
// 	_, err := mapRestErr(client.inner.PostSecretConfigWithResponse(ctx, body))
// 	return err
// }

// func (client *apiClient) PostSecretDestroy(ctx context.Context, path string, versions []int32) error {
// 	_, err := mapRestErr(client.inner.PostSecretDestroyWithResponse(ctx, path, types.SecretVersionsRequest{Versions: versions}))
// 	return err
// }

// func (client *apiClient) PostSecretMetadata(ctx context.Context, path string, body types.SecretUpdatableMetadata) error {
// 	_, err := mapRestErr(client.inner.PostSecretMetadataWithResponse(ctx, path, body))
// 	return err
// }

// func (client *apiClient) PostSecretRequest(ctx context.Context, path string, body types.PostSecretRequest) (*types.PostSecretResponse, error) {
// 	r, err := mapRestErr(client.inner.PostSecretRequestWithResponse(ctx, path, body))
// 	if err != nil {
// 		return nil, err
// 	}
// 	return r.JSON200, err
// }

// func (client *apiClient) PostSecretUndelete(ctx context.Context, path string, versions []int32) error {
// 	_, err := mapRestErr(client.inner.PostSecretUndeleteWithResponse(ctx, path, types.SecretVersionsRequest{Versions: versions}))
// 	return err
// }

func mapRestErr[T interface{ StatusCode() int }](resp T, err error) (T, error) {
	if err != nil {
		return resp, err
	}
	statusCode := resp.StatusCode()
	if statusCode >= 400 { // Everything below 400 is not an error
		// Use reflection to pick the errors from the HTTP response
		rresp := reflect.Indirect(reflect.ValueOf(resp))
		httpErr := httpError{code: statusCode, cause: nil}

		body := rresp.FieldByName("Body")
		if body.IsValid() && !body.IsNil() {
			httpErr.cause = NewKmsErrorFromBytes(body.Interface().([]byte))
		}
		return resp, httpErr
	}
	return resp, nil
}

type httpError struct {
	code  int
	cause error
}

func (err httpError) Error() string {
	return fmt.Sprintf("HTTP request failed - HTTP Status: %d, %s\n%s", err.code, http.StatusText(err.code), err.cause)
}

func (err httpError) Unwrap() error {
	return err.cause
}

// ErrStatusCode returns the status code of the HTTP response that caused this error, if any.
// If err is nil, or if it was not caused by an http response (for example if it was in fact
// caused by a connectivity issue), then it returns 0.
//
// The returned status code will be 0, or a value >= 400.
func ErrStatusCode(err error) int {
	if err != nil {
		var e httpError
		if errors.As(err, &e) {
			return e.code
		}
	}
	return 0
}
