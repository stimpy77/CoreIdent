using Microsoft.IdentityModel.Tokens;

namespace CoreIdent.Core.Services;

public interface ISigningKeyProvider
{
    Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default);
    Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default);
    string Algorithm { get; }
}

public record SecurityKeyInfo(string KeyId, SecurityKey Key, DateTime? ExpiresAt);
