using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite; // Required for SqliteException
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of IUserStore.
/// </summary>
public class EfUserStore : IUserStore
{
    protected readonly CoreIdentDbContext Context;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ILogger<EfUserStore> _logger;

    public EfUserStore(CoreIdentDbContext context, IPasswordHasher passwordHasher, ILoggerFactory loggerFactory)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));
        _logger = loggerFactory.CreateLogger<EfUserStore>();
    }

    // --- Core User Methods ---

    public virtual async Task<StoreResult> CreateUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        _logger.LogDebug("Attempting to add user {Username} ({UserId}) to context.", user.UserName, user.Id);
        Context.Users.Add(user);
        try
        {
            var changes = await Context.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("SaveChangesAsync completed for CreateUserAsync. {Changes} changes saved for user {Username} ({UserId}).", changes, user.UserName, user.Id);

            // --- Add verification step ---
            _logger.LogDebug("Verifying user {UserId} presence immediately after save.", user.Id);
            var verifyUser = await this.FindUserByIdAsync(user.Id, CancellationToken.None); // Use CancellationToken.None for verification
            if (verifyUser == null)
            {
                 _logger.LogError("VERIFICATION FAILED: User {UserId} not found immediately after SaveChangesAsync! Returning Failure.", user.Id);
                return StoreResult.Failure; // Indicate failure if verification fails
            }
             _logger.LogDebug("Verification successful: User {UserId} found immediately after save.", user.Id);
            // --- End verification step ---

            return StoreResult.Success;
        }
        catch (DbUpdateException ex) 
        {
            if (ex.InnerException is SqliteException sqliteEx && sqliteEx.SqliteErrorCode == 19)
            {
                 _logger.LogWarning(sqliteEx, "SQLite unique constraint violation during user creation for {Username}. Result: Conflict", user.UserName);
                return StoreResult.Conflict;
            }
             _logger.LogError(ex, "DbUpdateException during user creation for {Username}. Result: Conflict/Failure", user.UserName);
            return StoreResult.Conflict; 
        }
    }

    public virtual Task<CoreIdentUser?> FindUserByIdAsync(string userId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(userId);

        return Context.Users.FindAsync(new object[] { userId }, cancellationToken).AsTask();
    }

    public virtual async Task<CoreIdentUser?> FindUserByUsernameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(normalizedUserName);
        _logger.LogDebug("Executing FindUserByUsernameAsync for normalized username: {NormalizedUsername}", normalizedUserName);
        var user = await Context.Users
           // .AsNoTracking() // Try this if tracking seems to be the issue
           .FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedUserName, cancellationToken);
        _logger.LogDebug("FindUserByUsernameAsync result for {NormalizedUsername}: {FoundStatus}", normalizedUserName, user == null ? "Not Found" : $"Found (UserId: {user.Id})");
        return user;
    }

    // --- User Update/Delete ---

    public virtual async Task<StoreResult> UpdateUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);

        Context.Users.Attach(user);
        user.ConcurrencyStamp = Guid.NewGuid().ToString(); // Update concurrency stamp if using
        Context.Users.Update(user);

        try
        {
            await Context.SaveChangesAsync(cancellationToken);
            return StoreResult.Success;
        }
        catch (DbUpdateConcurrencyException) // Handle concurrency conflicts
        {
            return StoreResult.Failure; // Or a specific concurrency failure result
        }
        catch (DbUpdateException) // Handle other potential issues (like unique constraints if username changes)
        {
            return StoreResult.Conflict;
        }
    }

    public virtual async Task<StoreResult> DeleteUserAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);

        Context.Users.Attach(user);
        Context.Users.Remove(user);

        try
        {
            await Context.SaveChangesAsync(cancellationToken);
            return StoreResult.Success;
        }
        catch (DbUpdateConcurrencyException)
        {
            return StoreResult.Failure;
        }
        // No DbUpdateException expected on delete unless DB schema issue
    }

    // --- User Name Normalization ---

    public virtual Task<string?> GetNormalizedUserNameAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult(user.NormalizedUserName);
    }

    public virtual Task SetNormalizedUserNameAsync(CoreIdentUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    // --- Password Hashing ---

    public virtual Task SetPasswordHashAsync(CoreIdentUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }

    public virtual Task<string?> GetPasswordHashAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult(user.PasswordHash);
    }

    public virtual Task<bool> HasPasswordAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));
    }

    // --- Claim Management ---

    public virtual async Task<IList<Claim>> GetClaimsAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);

        var userClaims = await Context.UserClaims
            .Where(uc => uc.UserId == user.Id)
            .Select(uc => new Claim(uc.ClaimType ?? "", uc.ClaimValue ?? "")) // Handle potential nulls
            .ToListAsync(cancellationToken);
        return userClaims;
    }

    public virtual async Task AddClaimsAsync(CoreIdentUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);

        foreach (var claim in claims)
        {
            Context.UserClaims.Add(CreateUserClaim(user, claim));
        }
        // Consider batching if AddRangeAsync is available and performs better
        await Context.SaveChangesAsync(cancellationToken);
    }

    protected virtual CoreIdentUserClaim CreateUserClaim(CoreIdentUser user, Claim claim)
    {
        var userClaim = new CoreIdentUserClaim { UserId = user.Id };
        userClaim.InitializeFromClaim(claim);
        return userClaim;
    }

    public virtual async Task ReplaceClaimAsync(CoreIdentUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(newClaim);

        var matchedClaims = await Context.UserClaims
            .Where(uc => uc.UserId == user.Id && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type)
            .ToListAsync(cancellationToken);

        foreach (var matchedClaim in matchedClaims)
        {
            matchedClaim.ClaimType = newClaim.Type;
            matchedClaim.ClaimValue = newClaim.Value;
            Context.UserClaims.Update(matchedClaim);
        }
        await Context.SaveChangesAsync(cancellationToken);
    }

    public virtual async Task RemoveClaimsAsync(CoreIdentUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);

        foreach (var claim in claims)
        {
            var matchedClaims = await Context.UserClaims
                .Where(uc => uc.UserId == user.Id && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type)
                .ToListAsync(cancellationToken);
            Context.UserClaims.RemoveRange(matchedClaims);
        }
        await Context.SaveChangesAsync(cancellationToken);
    }

    public virtual async Task<IList<CoreIdentUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(claim);

        var query = from userclaims in Context.UserClaims
                    where userclaims.ClaimValue == claim.Value && userclaims.ClaimType == claim.Type
                    join user in Context.Users on userclaims.UserId equals user.Id
                    select user;

        return await query.Distinct().ToListAsync(cancellationToken);
    }

    // --- Lockout Management ---

    public virtual Task<int> GetAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult(user.AccessFailedCount);
    }

    public virtual Task<bool> GetLockoutEnabledAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult(user.LockoutEnabled);
    }

    public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        return Task.FromResult(user.LockoutEnd);
    }

    public virtual Task<int> IncrementAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        user.AccessFailedCount++;
        // Note: This doesn't save to DB immediately. UpdateUserAsync must be called.
        // This matches ASP.NET Core Identity behavior where UserManager coordinates.
        return Task.FromResult(user.AccessFailedCount);
    }

    public virtual Task ResetAccessFailedCountAsync(CoreIdentUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        user.AccessFailedCount = 0;
        // Note: Doesn't save to DB. UpdateUserAsync must be called.
        return Task.CompletedTask;
    }

    public virtual Task SetLockoutEndDateAsync(CoreIdentUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        user.LockoutEnd = lockoutEnd;
        // Note: Doesn't save to DB. UpdateUserAsync must be called.
        return Task.CompletedTask;
    }

    public virtual Task SetLockoutEnabledAsync(CoreIdentUser user, bool enabled, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(user);
        user.LockoutEnabled = enabled;
        // Note: Doesn't save to DB. UpdateUserAsync must be called.
        return Task.CompletedTask;
    }

    // Default implementation using PasswordHasher for stores that don't delegate
    public virtual async Task<PasswordVerificationResult> ValidateCredentialsAsync(string normalizedUserName, string password, CancellationToken cancellationToken)
    {
        var user = await FindUserByUsernameAsync(normalizedUserName, cancellationToken);
        if (user == null || user.PasswordHash == null)
        {
            return PasswordVerificationResult.Failed;
        }

        return _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
    }
} 