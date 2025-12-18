using System.Text;
using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Services;

/// <summary>
/// Symmetric (HS256) signing key provider intended for development/testing only.
/// </summary>
public class SymmetricSigningKeyProvider : ISigningKeyProvider
{
    private readonly CoreIdentKeyOptions _options;
    private readonly ILogger<SymmetricSigningKeyProvider> _logger;

    /// <inheritdoc />
    public string Algorithm => SecurityAlgorithms.HmacSha256;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="options">Key options.</param>
    /// <param name="logger">Logger.</param>
    public SymmetricSigningKeyProvider(IOptions<CoreIdentKeyOptions> options, ILogger<SymmetricSigningKeyProvider> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _logger.LogWarning(
            "Symmetric (HS256) signing is deprecated and intended for development/testing only. " +
            "Use RSA (RS256) or ECDSA (ES256) for production.");
    }

    /// <inheritdoc />
    public Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default)
    {
        var key = GetKey();
        var credentials = new SigningCredentials(key, Algorithm);
        return Task.FromResult(credentials);
    }

    /// <inheritdoc />
    public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default)
    {
        var key = GetKey();
        var keyInfo = new SecurityKeyInfo(key.KeyId ?? string.Empty, key, expiresAt: null);
        return Task.FromResult<IEnumerable<SecurityKeyInfo>>([keyInfo]);
    }

    private SymmetricSecurityKey GetKey()
    {
        if (string.IsNullOrWhiteSpace(_options.SymmetricKey))
        {
            throw new InvalidOperationException("SymmetricKey is required when using KeyType.Symmetric.");
        }

        var bytes = Encoding.UTF8.GetBytes(_options.SymmetricKey);
        if (bytes.Length < 32)
        {
            throw new InvalidOperationException("SymmetricKey must be at least 32 bytes (256 bits) for HS256.");
        }

        var key = new SymmetricSecurityKey(bytes)
        {
            KeyId = "symm-dev"
        };

        return key;
    }
}
