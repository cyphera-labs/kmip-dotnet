// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Cyphera.Kmip;

/// <summary>
/// KMIP client -- connects to any KMIP 1.4 server via mTLS.
/// Supports all 27 KMIP 1.4 operations.
///
/// Usage:
///   using var client = new KmipClient(new KmipClientOptions
///   {
///       Host = "kmip-server.corp.internal",
///       ClientCert = "/path/to/client.pem",
///       ClientKey = "/path/to/client-key.pem",
///       CaCert = "/path/to/ca.pem",
///   });
///
///   var key = await client.FetchKeyAsync("my-key-name");
///   // key is a byte[] of raw key bytes
/// </summary>
public sealed class KmipClient : IDisposable
{
    /// <summary>Maximum KMIP response size (16MB).</summary>
    private const int MaxResponseSize = 16 * 1024 * 1024;

    private readonly string _host;
    private readonly int _port;
    private readonly TimeSpan _timeout;
    private readonly X509Certificate2 _clientCert;
    private readonly X509Certificate2Collection? _caCerts;
    private readonly bool _insecureSkipVerify;
    private TcpClient? _tcpClient;
    private SslStream? _sslStream;

    /// <param name="options">Connection options.</param>
    public KmipClient(KmipClientOptions options)
    {
        _host = options.Host;
        _port = options.Port;
        _timeout = TimeSpan.FromMilliseconds(options.TimeoutMs);
        _insecureSkipVerify = options.InsecureSkipVerify;

        _clientCert = LoadClientCertificate(options.ClientCert, options.ClientKey);

        if (options.CaCert != null)
        {
            _caCerts = new X509Certificate2Collection();
            _caCerts.ImportFromPemFile(options.CaCert);
        }
    }

    // -----------------------------------------------------------------------
    // 1. Create
    // -----------------------------------------------------------------------

    /// <summary>Create a new symmetric key on the server.</summary>
    public async Task<CreateResult> CreateAsync(
        string name,
        string? algorithm = null,
        int length = 256,
        CancellationToken ct = default)
    {
        uint algoEnum = ResolveAlgorithm(algorithm);
        var request = Operations.BuildCreateRequest(name, algoEnum, length);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseCreatePayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 2. CreateKeyPair
    // -----------------------------------------------------------------------

    /// <summary>Create a new asymmetric key pair on the server.</summary>
    public async Task<CreateKeyPairResult> CreateKeyPairAsync(
        string name,
        uint algorithm,
        int length,
        CancellationToken ct = default)
    {
        var request = Operations.BuildCreateKeyPairRequest(name, algorithm, length);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseCreateKeyPairPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 3. Register
    // -----------------------------------------------------------------------

    /// <summary>Register existing key material on the server.</summary>
    public async Task<CreateResult> RegisterAsync(
        uint objectType,
        byte[] material,
        string name,
        uint algorithm,
        int length,
        CancellationToken ct = default)
    {
        var request = Operations.BuildRegisterRequest(objectType, material, name, algorithm, length);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseCreatePayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 4. ReKey
    // -----------------------------------------------------------------------

    /// <summary>Re-key an existing key on the server.</summary>
    public async Task<ReKeyResult> ReKeyAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildReKeyRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseReKeyPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 5. DeriveKey
    // -----------------------------------------------------------------------

    /// <summary>Derive a new key from an existing key.</summary>
    public async Task<DeriveKeyResult> DeriveKeyAsync(
        string uniqueId,
        byte[] derivationData,
        string name,
        int length,
        CancellationToken ct = default)
    {
        var request = Operations.BuildDeriveKeyRequest(uniqueId, derivationData, name, length);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseDeriveKeyPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 6. Locate
    // -----------------------------------------------------------------------

    /// <summary>Locate keys by name.</summary>
    public async Task<List<string>> LocateAsync(string name, CancellationToken ct = default)
    {
        var request = Operations.BuildLocateRequest(name);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseLocatePayload(response.Payload!).UniqueIdentifiers;
    }

    // -----------------------------------------------------------------------
    // 7. Check
    // -----------------------------------------------------------------------

    /// <summary>Check the status of a managed object.</summary>
    public async Task<CheckResult> CheckAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildCheckRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseCheckPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 8. Get
    // -----------------------------------------------------------------------

    /// <summary>Get key material by unique ID.</summary>
    public async Task<GetResult> GetAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildGetRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseGetPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 9. GetAttributes
    // -----------------------------------------------------------------------

    /// <summary>Fetch all attributes of a managed object.</summary>
    public async Task<GetResult> GetAttributesAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildGetAttributesRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseGetPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 10. GetAttributeList
    // -----------------------------------------------------------------------

    /// <summary>Fetch the list of attribute names for a managed object.</summary>
    public async Task<List<string>> GetAttributeListAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildGetAttributeListRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        if (response.Payload == null)
            return new List<string>();
        var attrs = Ttlv.FindChildren(response.Payload, Tag.AttributeName);
        return attrs
            .Where(a => a.TextValue != null)
            .Select(a => a.TextValue!)
            .ToList();
    }

    // -----------------------------------------------------------------------
    // 11. AddAttribute
    // -----------------------------------------------------------------------

    /// <summary>Add an attribute to a managed object.</summary>
    public async Task AddAttributeAsync(string uniqueId, string name, string value, CancellationToken ct = default)
    {
        var request = Operations.BuildAddAttributeRequest(uniqueId, name, value);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 12. ModifyAttribute
    // -----------------------------------------------------------------------

    /// <summary>Modify an attribute of a managed object.</summary>
    public async Task ModifyAttributeAsync(string uniqueId, string name, string value, CancellationToken ct = default)
    {
        var request = Operations.BuildModifyAttributeRequest(uniqueId, name, value);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 13. DeleteAttribute
    // -----------------------------------------------------------------------

    /// <summary>Delete an attribute from a managed object.</summary>
    public async Task DeleteAttributeAsync(string uniqueId, string name, CancellationToken ct = default)
    {
        var request = Operations.BuildDeleteAttributeRequest(uniqueId, name);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 14. ObtainLease
    // -----------------------------------------------------------------------

    /// <summary>Obtain a lease for a managed object. Returns lease time in seconds.</summary>
    public async Task<int> ObtainLeaseAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildObtainLeaseRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        if (response.Payload == null)
            return 0;
        var lease = Ttlv.FindChild(response.Payload, Tag.LeaseTime);
        return lease?.IntegerValue ?? 0;
    }

    // -----------------------------------------------------------------------
    // 15. Activate
    // -----------------------------------------------------------------------

    /// <summary>Activate a key by unique ID.</summary>
    public async Task ActivateAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildActivateRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 16. Revoke
    // -----------------------------------------------------------------------

    /// <summary>Revoke a managed object with the given reason code.</summary>
    public async Task RevokeAsync(string uniqueId, uint reason, CancellationToken ct = default)
    {
        var request = Operations.BuildRevokeRequest(uniqueId, reason);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 17. Destroy
    // -----------------------------------------------------------------------

    /// <summary>Destroy a key by unique ID.</summary>
    public async Task DestroyAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildDestroyRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 18. Archive
    // -----------------------------------------------------------------------

    /// <summary>Archive a managed object.</summary>
    public async Task ArchiveAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildArchiveRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 19. Recover
    // -----------------------------------------------------------------------

    /// <summary>Recover an archived managed object.</summary>
    public async Task RecoverAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildRecoverRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 20. Query
    // -----------------------------------------------------------------------

    /// <summary>Query the server for supported operations and object types.</summary>
    public async Task<QueryResult> QueryAsync(CancellationToken ct = default)
    {
        var request = Operations.BuildQueryRequest();
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseQueryPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 21. Poll
    // -----------------------------------------------------------------------

    /// <summary>Poll the server.</summary>
    public async Task PollAsync(CancellationToken ct = default)
    {
        var request = Operations.BuildPollRequest();
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        Operations.ParseResponse(responseData);
    }

    // -----------------------------------------------------------------------
    // 22. DiscoverVersions
    // -----------------------------------------------------------------------

    /// <summary>Discover the KMIP versions supported by the server.</summary>
    public async Task<DiscoverVersionsResult> DiscoverVersionsAsync(CancellationToken ct = default)
    {
        var request = Operations.BuildDiscoverVersionsRequest();
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseDiscoverVersionsPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 23. Encrypt
    // -----------------------------------------------------------------------

    /// <summary>Encrypt data using a managed key.</summary>
    public async Task<EncryptResult> EncryptAsync(string uniqueId, byte[] data, CancellationToken ct = default)
    {
        var request = Operations.BuildEncryptRequest(uniqueId, data);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseEncryptPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 24. Decrypt
    // -----------------------------------------------------------------------

    /// <summary>Decrypt data using a managed key.</summary>
    public async Task<DecryptResult> DecryptAsync(string uniqueId, byte[] data, byte[]? nonce = null, CancellationToken ct = default)
    {
        var request = Operations.BuildDecryptRequest(uniqueId, data, nonce);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseDecryptPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 25. Sign
    // -----------------------------------------------------------------------

    /// <summary>Sign data using a managed key.</summary>
    public async Task<SignResult> SignAsync(string uniqueId, byte[] data, CancellationToken ct = default)
    {
        var request = Operations.BuildSignRequest(uniqueId, data);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseSignPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 26. SignatureVerify
    // -----------------------------------------------------------------------

    /// <summary>Verify a signature using a managed key.</summary>
    public async Task<SignatureVerifyResult> SignatureVerifyAsync(string uniqueId, byte[] data, byte[] signature, CancellationToken ct = default)
    {
        var request = Operations.BuildSignatureVerifyRequest(uniqueId, data, signature);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseSignatureVerifyPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // 27. MAC
    // -----------------------------------------------------------------------

    /// <summary>Compute a MAC using a managed key.</summary>
    public async Task<MacResult> MacAsync(string uniqueId, byte[] data, CancellationToken ct = default)
    {
        var request = Operations.BuildMacRequest(uniqueId, data);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseMacPayload(response.Payload!);
    }

    // -----------------------------------------------------------------------
    // Convenience methods
    // -----------------------------------------------------------------------

    /// <summary>Convenience: locate by name + get material in one call.</summary>
    public async Task<byte[]> FetchKeyAsync(string name, CancellationToken ct = default)
    {
        var ids = await LocateAsync(name, ct).ConfigureAwait(false);
        if (ids.Count == 0)
            throw new KmipException($"KMIP: no key found with name \"{name}\"");

        var result = await GetAsync(ids[0], ct).ConfigureAwait(false);
        if (result.KeyMaterial == null)
            throw new KmipException($"KMIP: key \"{name}\" ({ids[0]}) has no extractable material");

        return result.KeyMaterial;
    }

    // -----------------------------------------------------------------------
    // Algorithm resolution
    // -----------------------------------------------------------------------

    /// <summary>Convert an algorithm name string to its KMIP enum value.</summary>
    public static uint ResolveAlgorithm(string? name)
    {
        return name?.ToUpperInvariant() switch
        {
            "AES" or null => KmipAlgorithm.Aes,
            "DES" => KmipAlgorithm.Des,
            "TRIPLEDES" or "3DES" => KmipAlgorithm.TripleDes,
            "RSA" => KmipAlgorithm.Rsa,
            "DSA" => KmipAlgorithm.Dsa,
            "ECDSA" => KmipAlgorithm.Ecdsa,
            "HMACSHA1" => KmipAlgorithm.HmacSha1,
            "HMACSHA256" => KmipAlgorithm.HmacSha256,
            "HMACSHA384" => KmipAlgorithm.HmacSha384,
            "HMACSHA512" => KmipAlgorithm.HmacSha512,
            _ => KmipAlgorithm.Aes,
        };
    }

    // -----------------------------------------------------------------------
    // Connection / transport
    // -----------------------------------------------------------------------

    /// <summary>Close the TLS connection.</summary>
    public void Dispose()
    {
        _sslStream?.Dispose();
        _sslStream = null;
        _tcpClient?.Dispose();
        _tcpClient = null;
        _clientCert.Dispose();
    }

    /// <summary>Send a KMIP request and receive the response.</summary>
    private async Task<byte[]> SendAsync(byte[] request, CancellationToken ct)
    {
        var stream = await ConnectAsync(ct).ConfigureAwait(false);

        try
        {
            await stream.WriteAsync(request, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }
        catch (IOException)
        {
            MarkStale(); // Mark connection as stale.
            throw;
        }

        // Read the TTLV header (8 bytes) to determine total length
        var header = new byte[8];
        try
        {
            await ReadExactAsync(stream, header, ct).ConfigureAwait(false);
        }
        catch (IOException)
        {
            MarkStale(); // Mark connection as stale.
            throw;
        }

        uint valueLength = (uint)((header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7]);

        // Validate response size before allocating.
        if (valueLength > MaxResponseSize)
        {
            MarkStale();
            throw new IOException(
                $"KMIP: response too large ({valueLength} bytes, max {MaxResponseSize})");
        }

        int totalLength = 8 + (int)valueLength;
        var buf = new byte[totalLength];
        Array.Copy(header, buf, 8);
        try
        {
            await ReadExactAsync(stream, buf.AsMemory(8), ct).ConfigureAwait(false);
        }
        catch (IOException)
        {
            MarkStale(); // Mark connection as stale.
            throw;
        }

        return buf;
    }

    /// <summary>Mark the current connection as stale so the next call reconnects.</summary>
    private void MarkStale()
    {
        _sslStream?.Dispose();
        _sslStream = null;
        _tcpClient?.Dispose();
        _tcpClient = null;
    }

    /// <summary>Establish or reuse the mTLS connection.</summary>
    private async Task<SslStream> ConnectAsync(CancellationToken ct)
    {
        if (_sslStream != null && _tcpClient != null && _tcpClient.Connected)
            return _sslStream;

        _sslStream?.Dispose();
        _tcpClient?.Dispose();

        _tcpClient = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);

        await _tcpClient.ConnectAsync(_host, _port, cts.Token).ConfigureAwait(false);

        // Only disable certificate validation if explicitly opted in via InsecureSkipVerify.
        // When no CA cert is provided, the system certificate store is used by default.
        RemoteCertificateValidationCallback? validationCallback = null;
        if (_insecureSkipVerify)
        {
            validationCallback = (sender, certificate, chain, errors) => true;
        }

        _sslStream = new SslStream(
            _tcpClient.GetStream(),
            leaveInnerStreamOpen: false,
            validationCallback);

        var authOptions = new SslClientAuthenticationOptions
        {
            TargetHost = _host,
            ClientCertificates = new X509Certificate2Collection(_clientCert),
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        };

        await _sslStream.AuthenticateAsClientAsync(authOptions, cts.Token).ConfigureAwait(false);

        return _sslStream;
    }

    /// <summary>Read exactly the specified number of bytes from the stream.</summary>
    private static async Task ReadExactAsync(SslStream stream, Memory<byte> buffer, CancellationToken ct)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[totalRead..], ct).ConfigureAwait(false);
            if (read == 0)
                throw new IOException("Connection closed while reading KMIP response");
            totalRead += read;
        }
    }

    /// <summary>Load a client certificate with private key from PEM files.</summary>
    private static X509Certificate2 LoadClientCertificate(string certPath, string keyPath)
    {
        return X509Certificate2.CreateFromPemFile(certPath, keyPath);
    }
}

/// <summary>KMIP client connection options.</summary>
public sealed class KmipClientOptions
{
    /// <summary>KMIP server hostname.</summary>
    public required string Host { get; init; }

    /// <summary>KMIP server port (default 5696).</summary>
    public int Port { get; init; } = 5696;

    /// <summary>Path to client certificate PEM file.</summary>
    public required string ClientCert { get; init; }

    /// <summary>Path to client private key PEM file.</summary>
    public required string ClientKey { get; init; }

    /// <summary>Optional path to CA certificate PEM file (uses system roots if not set).</summary>
    public string? CaCert { get; init; }

    /// <summary>Connection timeout in milliseconds (default 10000).</summary>
    public int TimeoutMs { get; init; } = 10000;

    /// <summary>DANGER: disables server certificate verification (default false).</summary>
    public bool InsecureSkipVerify { get; init; } = false;
}
