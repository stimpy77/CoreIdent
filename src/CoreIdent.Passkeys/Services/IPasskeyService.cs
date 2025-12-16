using CoreIdent.Core.Models;

namespace CoreIdent.Passkeys.Services;

public interface IPasskeyService
{
    Task<string> GetRegistrationOptionsJsonAsync(CoreIdentUser user, CancellationToken ct = default);

    Task CompleteRegistrationAsync(CoreIdentUser user, string credentialJson, CancellationToken ct = default);

    Task<string> GetAuthenticationOptionsJsonAsync(string? username, CancellationToken ct = default);

    Task<CoreIdentUser?> AuthenticateAsync(string credentialJson, CancellationToken ct = default);
}
