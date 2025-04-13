using CoreIdent.Core.Stores;
using CoreIdent.Core.Models;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Collections.Generic;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Adapters.DelegatedUserStore;

/// <summary>
/// An IUserStore implementation that delegates user management operations
/// to functions provided via DelegatedUserStoreOptions.
/// </summary>
public sealed class DelegatedUserStore : IUserStore, IDisposable
{
    private readonly DelegatedUserStoreOptions _options;

    public DelegatedUserStore(IOptions<DelegatedUserStoreOptions> options)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options), "DelegatedUserStoreOptions cannot be null.");
    }

    public async Task<CoreIdentUser?> FindUserByIdAsync(string userId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        if (_options.FindUserByIdAsync is null)
        {
            throw new InvalidOperationException($"{nameof(_options.FindUserByIdAsync)} delegate must be configured.");
        }
        return await _options.FindUserByIdAsync(userId, cancellationToken);
    }

    public async Task<CoreIdentUser?> FindUserByUsernameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedUserName);
        if (_options.FindUserByUsernameAsync is null)
        {
            throw new InvalidOperationException($"{nameof(_options.FindUserByUsernameAsync)} delegate must be configured.");
        }
        // Assuming the provided delegate handles normalization if necessary, or expects normalized input.
        return await _options.FindUserByUsernameAsync(normalizedUserName, cancellationToken);
    }

    public Task<string?> GetUserIdAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        // Explicitly return Task<string?> to match interface
        return Task.FromResult<string?>(user.Id);
    }

    public Task<string?> GetUsernameAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult<string?>(user.UserName);
    }

    public Task<string?> GetNormalizedUserNameAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        // Assuming username is already normalized or normalization happens externally.
        return Task.FromResult(user.NormalizedUserName);
    }

    public async Task<IList<Claim>> GetClaimsAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (_options.GetClaimsAsync is not null)
        {
            return await _options.GetClaimsAsync(user, cancellationToken);
        }
        // Default basic claims if delegate not provided
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id ?? string.Empty),
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty)
        };
        return claims;
    }

    public Task<bool> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (_options.ValidateCredentialsAsync is null)
        {
            throw new InvalidOperationException($"{nameof(_options.ValidateCredentialsAsync)} delegate must be configured.");
        }
        return _options.ValidateCredentialsAsync(username, password, cancellationToken);
    }

    public Task<string?> GetPasswordHashAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        // This store doesn't manage password hashes directly.
        return Task.FromResult<string?>(null);
    }

    public Task<bool> HasPasswordAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        // Assume users managed externally always have credentials.
        return Task.FromResult(true);
    }

    public Task SetPasswordHashAsync(CoreIdentUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        // This store delegates credential validation, doesn't set hashes.
        return Task.CompletedTask;
    }

    public Task SetUsernameAsync(CoreIdentUser user, string? username, CancellationToken cancellationToken)
    {
        throw new NotImplementedException("DelegatedUserStore does not support modifying usernames.");
    }

    public Task SetNormalizedUserNameAsync(CoreIdentUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        // Handled implicitly or externally
        return Task.CompletedTask;
    }

    public Task<StoreResult> CreateUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException("DelegatedUserStore does not support creating users.");
    }

    public Task<StoreResult> UpdateUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException("DelegatedUserStore does not support updating users.");
    }

    public Task<StoreResult> DeleteUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException("DelegatedUserStore does not support deleting users.");
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        // No managed resources to dispose in this simple version.
        // If derived classes have resources, they should override this.
    }

    public Task AddClaimsAsync(CoreIdentUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        throw new NotImplementedException("DelegatedUserStore does not support adding claims.");
    }

    public Task RemoveClaimsAsync(CoreIdentUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        throw new NotImplementedException("DelegatedUserStore does not support removing claims.");
    }

    public Task ReplaceClaimAsync(CoreIdentUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
    {
        throw new NotImplementedException("DelegatedUserStore does not support replacing claims.");
    }

    public Task<IList<CoreIdentUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
        throw new NotImplementedException("DelegatedUserStore does not support querying users by claim.");
    }

    public Task<int> GetAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        // Assume external store handles this; return default.
        return Task.FromResult(0);
    }

    public Task<bool> GetLockoutEnabledAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        // Assume external store handles this; return default (false).
        return Task.FromResult(false);
    }

    public Task<DateTimeOffset?> GetLockoutEndDateAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        // Assume external store handles this; return default.
        return Task.FromResult<DateTimeOffset?>(null);
    }

    public Task<int> IncrementAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        // This store doesn't manage lockout.
        return Task.FromResult(0);
    }

    public Task ResetAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        // This store doesn't manage lockout.
        return Task.CompletedTask;
    }

    public Task SetLockoutEndDateAsync(CoreIdentUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        // This store doesn't manage lockout.
        return Task.CompletedTask;
    }

    public Task SetLockoutEnabledAsync(CoreIdentUser user, bool enabled, CancellationToken cancellationToken)
    {
        // This store doesn't manage lockout.
        return Task.CompletedTask;
    }
} 