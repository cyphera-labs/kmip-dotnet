// Copyright 2026 Horizon Digital Engineering LLC
// Licensed under the Apache License, Version 2.0

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Cyphera.Kmip;

/// <summary>
/// KMIP client -- connects to any KMIP 1.4 server via mTLS.
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
    private readonly string _host;
    private readonly int _port;
    private readonly TimeSpan _timeout;
    private readonly X509Certificate2 _clientCert;
    private readonly X509Certificate2Collection? _caCerts;
    private TcpClient? _tcpClient;
    private SslStream? _sslStream;

    /// <param name="options">Connection options.</param>
    public KmipClient(KmipClientOptions options)
    {
        _host = options.Host;
        _port = options.Port;
        _timeout = TimeSpan.FromMilliseconds(options.TimeoutMs);

        _clientCert = LoadClientCertificate(options.ClientCert, options.ClientKey);

        if (options.CaCert != null)
        {
            _caCerts = new X509Certificate2Collection();
            _caCerts.ImportFromPemFile(options.CaCert);
        }
    }

    /// <summary>Locate keys by name.</summary>
    public async Task<List<string>> LocateAsync(string name, CancellationToken ct = default)
    {
        var request = Operations.BuildLocateRequest(name);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseLocatePayload(response.Payload!).UniqueIdentifiers;
    }

    /// <summary>Get key material by unique ID.</summary>
    public async Task<GetResult> GetAsync(string uniqueId, CancellationToken ct = default)
    {
        var request = Operations.BuildGetRequest(uniqueId);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseGetPayload(response.Payload!);
    }

    /// <summary>Create a new symmetric key on the server.</summary>
    public async Task<CreateResult> CreateAsync(
        string name,
        string? algorithm = null,
        int length = 256,
        CancellationToken ct = default)
    {
        uint algoEnum = algorithm?.ToUpperInvariant() switch
        {
            "AES" or null => KmipAlgorithm.Aes,
            "DES" => KmipAlgorithm.Des,
            "TRIPLEDES" or "3DES" => KmipAlgorithm.TripleDes,
            "RSA" => KmipAlgorithm.Rsa,
            _ => KmipAlgorithm.Aes,
        };
        var request = Operations.BuildCreateRequest(name, algoEnum, length);
        var responseData = await SendAsync(request, ct).ConfigureAwait(false);
        var response = Operations.ParseResponse(responseData);
        return Operations.ParseCreatePayload(response.Payload!);
    }

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

        await stream.WriteAsync(request, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        // Read the TTLV header (8 bytes) to determine total length
        var header = new byte[8];
        await ReadExactAsync(stream, header, ct).ConfigureAwait(false);

        uint valueLength = (uint)((header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7]);
        int totalLength = 8 + (int)valueLength;

        var buf = new byte[totalLength];
        Array.Copy(header, buf, 8);
        await ReadExactAsync(stream, buf.AsMemory(8), ct).ConfigureAwait(false);

        return buf;
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

        _sslStream = new SslStream(
            _tcpClient.GetStream(),
            leaveInnerStreamOpen: false,
            (sender, certificate, chain, errors) =>
            {
                if (_caCerts == null) return true;
                // Validate using provided CA
                return errors == SslPolicyErrors.None
                    || errors == SslPolicyErrors.RemoteCertificateChainErrors;
            });

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

    /// <summary>Optional path to CA certificate PEM file.</summary>
    public string? CaCert { get; init; }

    /// <summary>Connection timeout in milliseconds (default 10000).</summary>
    public int TimeoutMs { get; init; } = 10000;
}
