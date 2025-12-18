using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Passkeys.Models;
using CoreIdent.Passkeys.Stores;
using Microsoft.AspNetCore.Identity;

namespace CoreIdent.Passkeys.AspNetIdentity.Stores;

/// <summary>
/// ASP.NET Core Identity adapter store that forwards CoreIdent user operations to <see cref="CoreIdent.Core.Stores.IUserStore"/>
/// and passkey operations to <see cref="IPasskeyCredentialStore"/>.
/// </summary>
public sealed class CoreIdentIdentityUserStore : IUserStore<CoreIdentUser>, IUserPasskeyStore<CoreIdentUser>
{
    private readonly CoreIdent.Core.Stores.IUserStore _userStore;
    private readonly IPasskeyCredentialStore _passkeyCredentialStore;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoreIdentIdentityUserStore"/> class.
    /// </summary>
    /// <param name="userStore">The CoreIdent user store.</param>
    /// <param name="passkeyCredentialStore">The passkey credential store.</param>
    public CoreIdentIdentityUserStore(CoreIdent.Core.Stores.IUserStore userStore, IPasskeyCredentialStore passkeyCredentialStore)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _passkeyCredentialStore = passkeyCredentialStore ?? throw new ArgumentNullException(nameof(passkeyCredentialStore));
    }

    /// <inheritdoc />
    public void Dispose()
    {
    }

    /// <inheritdoc />
    public Task<string> GetUserIdAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult(user.Id);
    }

    /// <inheritdoc />
    public Task<string?> GetUserNameAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult<string?>(user.UserName);
    }

    /// <inheritdoc />
    public Task SetUserNameAsync(CoreIdentUser user, string? userName, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        user.UserName = userName ?? string.Empty;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<string?> GetNormalizedUserNameAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult<string?>(user.NormalizedUserName);
    }

    /// <inheritdoc />
    public Task SetNormalizedUserNameAsync(CoreIdentUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        user.NormalizedUserName = normalizedName ?? string.Empty;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task<IdentityResult> CreateAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        await _userStore.CreateAsync(user, cancellationToken);
        return IdentityResult.Success;
    }

    /// <inheritdoc />
    public async Task<IdentityResult> UpdateAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        await _userStore.UpdateAsync(user, cancellationToken);
        return IdentityResult.Success;
    }

    /// <inheritdoc />
    public async Task<IdentityResult> DeleteAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        await _userStore.DeleteAsync(user.Id, cancellationToken);
        return IdentityResult.Success;
    }

    /// <inheritdoc />
    public Task<CoreIdentUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        return _userStore.FindByIdAsync(userId, cancellationToken);
    }

    /// <inheritdoc />
    public Task<CoreIdentUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        return _userStore.FindByUsernameAsync(normalizedUserName, cancellationToken);
    }

    /// <inheritdoc />
    public async Task AddOrUpdatePasskeyAsync(CoreIdentUser user, UserPasskeyInfo passkey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(passkey);

        var credential = new PasskeyCredential
        {
            UserId = user.Id,
            CreatedAt = passkey.CreatedAt == default ? DateTimeOffset.UtcNow : passkey.CreatedAt,
            CredentialId = passkey.CredentialId,
            PublicKey = passkey.PublicKey,
            SignatureCounter = passkey.SignCount,
            Transports = passkey.Transports?.ToArray(),
            IsBackedUp = passkey.IsBackedUp,
            IsBackupEligible = passkey.IsBackupEligible,
            AttestationObject = passkey.AttestationObject,
            ClientDataJson = passkey.ClientDataJson,
            Name = passkey.Name,
        };

        await _passkeyCredentialStore.UpsertAsync(credential, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<CoreIdentUser?> FindByPasskeyIdAsync(byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        var stored = await _passkeyCredentialStore.GetByCredentialIdAsync(credentialId, cancellationToken);
        if (stored is null)
        {
            return null;
        }

        return await _userStore.FindByIdAsync(stored.UserId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<UserPasskeyInfo?> FindPasskeyAsync(CoreIdentUser user, byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(credentialId);

        var stored = await _passkeyCredentialStore.GetByCredentialIdAsync(credentialId, cancellationToken);
        if (stored is null || !string.Equals(stored.UserId, user.Id, StringComparison.Ordinal))
        {
            return null;
        }

        var info = new UserPasskeyInfo(
            stored.CredentialId,
            stored.PublicKey,
            createdAt: stored.CreatedAt,
            signCount: stored.SignatureCounter,
            transports: stored.Transports,
            isUserVerified: true,
            isBackupEligible: stored.IsBackupEligible,
            isBackedUp: stored.IsBackedUp,
            attestationObject: stored.AttestationObject ?? Array.Empty<byte>(),
            clientDataJson: stored.ClientDataJson ?? Array.Empty<byte>());

        info.Name = stored.Name;
        return info;
    }

    /// <inheritdoc />
    public async Task<IList<UserPasskeyInfo>> GetPasskeysAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);

        var list = await _passkeyCredentialStore.GetByUserIdAsync(user.Id, cancellationToken);

        return list
            .Select(stored =>
            {
                var info = new UserPasskeyInfo(
                    stored.CredentialId,
                    stored.PublicKey,
                    createdAt: stored.CreatedAt,
                    signCount: stored.SignatureCounter,
                    transports: stored.Transports,
                    isUserVerified: true,
                    isBackupEligible: stored.IsBackupEligible,
                    isBackedUp: stored.IsBackedUp,
                    attestationObject: stored.AttestationObject ?? Array.Empty<byte>(),
                    clientDataJson: stored.ClientDataJson ?? Array.Empty<byte>());

                info.Name = stored.Name;
                return info;
            })
            .ToList();
    }

    /// <inheritdoc />
    public async Task RemovePasskeyAsync(CoreIdentUser user, byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(credentialId);

        await _passkeyCredentialStore.DeleteAsync(user.Id, credentialId, cancellationToken);
    }
}
