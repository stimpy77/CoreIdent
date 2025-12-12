using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Services;

/// <summary>
/// RSA-based signing key provider supporting RS256 algorithm.
/// Loads keys from PEM string, PEM file, X509 certificate, or generates on startup (dev mode).
/// </summary>
public class RsaSigningKeyProvider : ISigningKeyProvider, IDisposable
{
    private readonly CoreIdentKeyOptions _options;
    private readonly ILogger<RsaSigningKeyProvider> _logger;
    private readonly Lazy<RsaSecurityKey> _signingKey;
    private readonly Lazy<string> _keyId;
    private bool _disposed;

    public string Algorithm => SecurityAlgorithms.RsaSha256;

    public RsaSigningKeyProvider(IOptions<CoreIdentKeyOptions> options, ILogger<RsaSigningKeyProvider> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _signingKey = new Lazy<RsaSecurityKey>(LoadOrGenerateKey);
        _keyId = new Lazy<string>(() => ComputeKeyId(_signingKey.Value));
    }

    public Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default)
    {
        var key = _signingKey.Value;
        key.KeyId = _keyId.Value;
        var credentials = new SigningCredentials(key, Algorithm);
        return Task.FromResult(credentials);
    }

    public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default)
    {
        var key = _signingKey.Value;
        key.KeyId = _keyId.Value;

        // Return only the public key for validation
        var publicKey = new RsaSecurityKey(key.Rsa.ExportParameters(includePrivateParameters: false))
        {
            KeyId = _keyId.Value
        };

        var keyInfo = new SecurityKeyInfo(_keyId.Value, publicKey, ExpiresAt: null);
        return Task.FromResult<IEnumerable<SecurityKeyInfo>>([keyInfo]);
    }

    private RsaSecurityKey LoadOrGenerateKey()
    {
        // Priority: PEM string > PEM file > Certificate > Generate
        if (!string.IsNullOrWhiteSpace(_options.PrivateKeyPem))
        {
            return LoadFromPemString(_options.PrivateKeyPem);
        }

        if (!string.IsNullOrWhiteSpace(_options.PrivateKeyPath))
        {
            return LoadFromPemFile(_options.PrivateKeyPath);
        }

        if (!string.IsNullOrWhiteSpace(_options.CertificatePath))
        {
            return LoadFromCertificate(_options.CertificatePath, _options.CertificatePassword);
        }

        // Dev mode: generate key on startup
        _logger.LogWarning(
            "No RSA key configured. Generating ephemeral {KeySize}-bit RSA key. " +
            "This is suitable for development only. Configure a persistent key for production.",
            _options.RsaKeySize);

        return GenerateKey(_options.RsaKeySize);
    }

    private RsaSecurityKey LoadFromPemString(string pem)
    {
        _logger.LogDebug("Loading RSA key from PEM string");
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return new RsaSecurityKey(rsa);
    }

    private RsaSecurityKey LoadFromPemFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"RSA key file not found: {path}", path);
        }

        _logger.LogDebug("Loading RSA key from PEM file: {Path}", path);
        var pem = File.ReadAllText(path);
        return LoadFromPemString(pem);
    }

    private RsaSecurityKey LoadFromCertificate(string path, string? password)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Certificate file not found: {path}", path);
        }

        _logger.LogDebug("Loading RSA key from certificate: {Path}", path);

        var cert = string.IsNullOrEmpty(password)
            ? X509CertificateLoader.LoadCertificateFromFile(path)
            : X509CertificateLoader.LoadPkcs12FromFile(path, password);

        var rsa = cert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Certificate does not contain an RSA private key.");

        return new RsaSecurityKey(rsa);
    }

    private static RsaSecurityKey GenerateKey(int keySize)
    {
        var rsa = RSA.Create(keySize);
        return new RsaSecurityKey(rsa);
    }

    private static string ComputeKeyId(RsaSecurityKey key)
    {
        var publicKeyBytes = key.Rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(publicKeyBytes);
        return Base64UrlEncoder.Encode(hash);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_signingKey.IsValueCreated)
        {
            _signingKey.Value.Rsa?.Dispose();
        }

        GC.SuppressFinalize(this);
    }
}
