# okms-sdk-go

[![Go Reference](https://pkg.go.dev/badge/github.com/ovh/okms-sdk-go.svg)](https://pkg.go.dev/github.com/ovh/okms-sdk-go) [![license](https://img.shields.io/badge/license-Apache%202.0-red.svg?style=flat)](https://raw.githubusercontent.com/ovh/okms-sdk-go/master/LICENSE) [![test](https://github.com/ovh/okms-sdk-go/actions/workflows/test.yaml/badge.svg)](https://github.com/ovh/okms-sdk-go/actions/workflows/test.yaml)

The Golang SDK to interact with your [OVHcloud KMS](https://help.ovhcloud.com/csm/en-ie-kms-quick-start?id=kb_article_view&sysparm_article=KB0063362) services.

> **NOTE:** THIS PROJECT IS CURRENTLY UNDER DEVELOPMENT AND SUBJECT TO BREAKING CHANGES.

## How to use
Add it to your project by running
```bash
go get github.com/ovh/okms-sdk-go@latest
```

Then you can connect to your KMS service
```go
cert, err := tls.LoadX509KeyPair(os.Getenv("KMS_CLIENT_CERT_FILE"), os.Getenv("KMS_CLIENT_KEY_FILE"))
if err != nil {
    panic(err)
}
httpClient := http.Client{
    Transport: &http.Transport{TLSClientConfig: &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS12,
    }},
}
kmsClient, err := okms.NewRestAPIClientWithHttp("https://eu-west-rbx.okms.ovh.net", &httpClient)
if err != nil {
    panic(err)
}

// Then start using the kmsClient
```

See [examples](./examples) for more.

If you don't have any KMS service yet, you can follow the [OVHcloud KMS quick start guide](https://help.ovhcloud.com/csm/en-ie-kms-quick-start?id=kb_article_view&sysparm_article=KB0063362).

## Features
Current SDK allows you to manipulate and consume keys through the KMS REST API. Implemented operations are
- Keys and Key Pairs lifecycle:
    - Create keys and key pairs
    - Import keys and key pairs
    - Activate and Deactivate keys and key pairs
    - Update keys and key pairs
    - Destroy keys and key pairs
    - Update keys and key pairs metadata
    - List keys and key pairs
    - Export key pair's public keys
    - Read keys and key pairs metadata
- Symmetric Key operations
    - Encrypt / Decrypt data
    - Generate data keys
    - Decrypt data keys
- Assymetric Key Pair operations
    - Sign / Verify data