# kmip-dotnet

[![CI](https://github.com/cyphera-labs/kmip-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/kmip-dotnet/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/kmip-dotnet/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/kmip-dotnet/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

KMIP client for .NET -- connect to any KMIP-compliant key management server.

Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix, HashiCorp Vault Enterprise, and any KMIP 1.4 server.

```
dotnet add package Cyphera.Kmip
```

## Quick Start

```csharp
using Cyphera.Kmip;

using var client = new KmipClient(new KmipClientOptions
{
    Host = "kmip-server.corp.internal",
    ClientCert = "/path/to/client.pem",
    ClientKey = "/path/to/client-key.pem",
    CaCert = "/path/to/ca.pem",
});

// Fetch a key by name (locate + get in one call)
byte[] key = await client.FetchKeyAsync("my-encryption-key");
// key is a byte[] of raw key bytes (e.g., 32 bytes for AES-256)

// Or step by step:
var ids = await client.LocateAsync("my-key");
var result = await client.GetAsync(ids[0]);
Console.WriteLine(BitConverter.ToString(result.KeyMaterial!));

// Create a new AES-256 key on the server
var created = await client.CreateAsync("new-key-name", "AES", 256);
Console.WriteLine(created.UniqueIdentifier);
```

## Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Locate | `client.LocateAsync(name)` | Find keys by name, returns unique IDs |
| Get | `client.GetAsync(id)` | Fetch key material by unique ID |
| Create | `client.CreateAsync(name, algo, length)` | Create a new symmetric key |
| Fetch | `client.FetchKeyAsync(name)` | Locate + Get in one call |

## Authentication

KMIP uses mutual TLS (mTLS). Provide:
- **Client certificate** -- identifies your application to the KMS
- **Client private key** -- proves ownership of the certificate
- **CA certificate** -- validates the KMS server's certificate

```csharp
using var client = new KmipClient(new KmipClientOptions
{
    Host = "kmip.corp.internal",
    Port = 5696,                    // default KMIP port
    ClientCert = "/etc/kmip/client.pem",
    ClientKey = "/etc/kmip/client-key.pem",
    CaCert = "/etc/kmip/ca.pem",
    TimeoutMs = 10000,              // connection timeout (ms)
});
```

## TTLV Codec

The low-level TTLV (Tag-Type-Length-Value) encoder/decoder is also exported for advanced use:

```csharp
using Cyphera.Kmip;

// Build custom KMIP messages
var msg = Ttlv.EncodeStructure(Tag.RequestMessage, /* ... */);

// Parse raw KMIP responses
var parsed = Ttlv.Decode(responseBytes);
```

## Supported KMS Servers

| Server | KMIP Version | Tested |
|--------|-------------|--------|
| Thales CipherTrust Manager | 1.x, 2.0 | Planned |
| IBM SKLM | 1.x, 2.0 | Planned |
| Entrust KeyControl | 1.x, 2.0 | Planned |
| Fortanix DSM | 2.0 | Planned |
| HashiCorp Vault Enterprise | 1.4 | Planned |
| PyKMIP (test server) | 1.0-2.0 | CI |

## Zero Dependencies

This library uses only .NET standard library (`SslStream`, `TcpClient`, `X509Certificate2`). No external dependencies beyond the test framework.

## Status

Alpha. KMIP 1.4 operations: Locate, Get, Create.

## License

Apache 2.0 -- Copyright 2026 Horizon Digital Engineering LLC
