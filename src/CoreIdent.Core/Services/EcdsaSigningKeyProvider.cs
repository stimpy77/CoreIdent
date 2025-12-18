using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Services;

/// <summary>
/// ECDSA-based signing key provider supporting ES256 algorithm (P-256 curve).
/// Loads keys from PEM string, PEM file, X509 certificate, or generates on startup (dev mode).
/// </summary>
public class EcdsaSigningKeyProvider : ISigningKeyProvider, IDisposable
{
    private readonly CoreIdentKeyOptions _options;
    private readonly ILogger<EcdsaSigningKeyProvider> _logger;
    private readonly Lazy<ECDsaSecurityKey> _signingKey;
    private readonly Lazy<string> _keyId;
    private bool _disposed;

    /// <inheritdoc />
    public string Algorithm => SecurityAlgorithms.EcdsaSha256;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="options">Key options.</param>
    /// <param name="logger">Logger.</param>
    public EcdsaSigningKeyProvider(IOptions<CoreIdentKeyOptions> options, ILogger<EcdsaSigningKeyProvider> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _signingKey = new Lazy<ECDsaSecurityKey>(LoadOrGenerateKey);
        _keyId = new Lazy<string>(() => ComputeKeyId(_signingKey.Value));
    }

    /// <inheritdoc />
    public Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default)
    {
        var key = _signingKey.Value;
        key.KeyId = _keyId.Value;
        var credentials = new SigningCredentials(key, Algorithm);
        return Task.FromResult(credentials);
    }

    /// <inheritdoc />
    public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default)
    {
        var key = _signingKey.Value;
        key.KeyId = _keyId.Value;

        // Return only the public key for validation
        var publicEcdsa = ECDsa.Create();
        publicEcdsa.ImportSubjectPublicKeyInfo(key.ECDsa.ExportSubjectPublicKeyInfo(), out _);
        var publicKey = new ECDsaSecurityKey(publicEcdsa)
        {
            KeyId = _keyId.Value
        };

        var keyInfo = new SecurityKeyInfo(_keyId.Value, publicKey, expiresAt: null);
        return Task.FromResult<IEnumerable<SecurityKeyInfo>>([keyInfo]);
    }

    private ECDsaSecurityKey LoadOrGenerateKey()
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
            "No ECDSA key configured. Generating ephemeral P-256 ECDSA key. " +
            "This is suitable for development only. Configure a persistent key for production.");

        return GenerateKey();
    }

    private ECDsaSecurityKey LoadFromPemString(string pem)
    {
        _logger.LogDebug("Loading ECDSA key from PEM string");
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return new ECDsaSecurityKey(ecdsa);
    }

    private ECDsaSecurityKey LoadFromPemFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"ECDSA key file not found: {path}", path);
        }

        _logger.LogDebug("Loading ECDSA key from PEM file: {Path}", path);
        var pem = File.ReadAllText(path);
        return LoadFromPemString(pem);
    }

    private ECDsaSecurityKey LoadFromCertificate(string path, string? password)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Certificate file not found: {path}", path);
        }

        _logger.LogDebug("Loading ECDSA key from certificate: {Path}", path);

        var cert = string.IsNullOrEmpty(password)
            ? X509CertificateLoader.LoadCertificateFromFile(path)
            : X509CertificateLoader.LoadPkcs12FromFile(path, password);

        var ecdsa = cert.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("Certificate does not contain an ECDSA private key.");

        return new ECDsaSecurityKey(ecdsa);
    }

    private static ECDsaSecurityKey GenerateKey()
    {
        // ES256 uses P-256 (secp256r1) curve
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new ECDsaSecurityKey(ecdsa);
    }

    private static string ComputeKeyId(ECDsaSecurityKey key)
    {
        var publicKeyBytes = key.ECDsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(publicKeyBytes);
        return Base64UrlEncoder.Encode(hash);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_signingKey.IsValueCreated)
        {
            _signingKey.Value.ECDsa?.Dispose();
        }

        GC.SuppressFinalize(this);
    }
}
