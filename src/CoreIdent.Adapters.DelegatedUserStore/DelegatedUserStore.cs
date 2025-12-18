using System.Security.Claims;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.Options;

namespace CoreIdent.Adapters.DelegatedUserStore;

/// <summary>
/// Adapter <see cref="IUserStore"/> implementation that delegates user lookups (and optionally claims) to host-provided callbacks.
/// </summary>
public sealed class DelegatedUserStore : IUserStore
{
    /// <summary>
    /// Placeholder value assigned to <see cref="CoreIdentUser.PasswordHash"/> for users returned by this store.
    /// </summary>
    public const string PasswordHashPlaceholder = "__COREIDENT_DELEGATED__";

    private readonly IOptions<DelegatedUserStoreOptions> _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="DelegatedUserStore"/> class.
    /// </summary>
    /// <param name="options">The delegated user store options.</param>
    public DelegatedUserStore(IOptions<DelegatedUserStoreOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    public async Task<CoreIdentUser?> FindByIdAsync(string id, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        var user = await _options.Value.FindUserByIdAsync!(id, ct);
        return Normalize(user);
    }

    /// <inheritdoc />
    public async Task<CoreIdentUser?> FindByUsernameAsync(string username, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        var user = await _options.Value.FindUserByUsernameAsync!(username, ct);
        return Normalize(user);
    }

    /// <inheritdoc />
    public Task CreateAsync(CoreIdentUser user, CancellationToken ct = default)
    {
        throw new NotSupportedException("Delegated user store does not support CreateAsync. Provide user creation via your existing user system.");
    }

    /// <inheritdoc />
    public Task UpdateAsync(CoreIdentUser user, CancellationToken ct = default)
    {
        throw new NotSupportedException("Delegated user store does not support UpdateAsync. Provide user updates via your existing user system.");
    }

    /// <inheritdoc />
    public Task DeleteAsync(string id, CancellationToken ct = default)
    {
        throw new NotSupportedException("Delegated user store does not support DeleteAsync. Provide user deletion via your existing user system.");
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<Claim>> GetClaimsAsync(string subjectId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return Array.Empty<Claim>();
        }

        var claimsProvider = _options.Value.GetClaimsAsync;
        if (claimsProvider is null)
        {
            return Array.Empty<Claim>();
        }

        var claims = await claimsProvider(subjectId, ct);
        return claims ?? Array.Empty<Claim>();
    }

    /// <inheritdoc />
    public Task SetClaimsAsync(string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default)
    {
        throw new NotSupportedException("Delegated user store does not support SetClaimsAsync. Provide claims management via your existing user system.");
    }

    private static CoreIdentUser? Normalize(CoreIdentUser? user)
    {
        if (user is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(user.NormalizedUserName) && !string.IsNullOrWhiteSpace(user.UserName))
        {
            user.NormalizedUserName = user.UserName.ToUpperInvariant();
        }

        user.PasswordHash = PasswordHashPlaceholder;

        return user;
    }
}
