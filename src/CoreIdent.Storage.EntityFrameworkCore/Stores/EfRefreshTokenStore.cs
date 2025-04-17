using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of IRefreshTokenStore.
/// </summary>
public class EfRefreshTokenStore : IRefreshTokenStore
{
    protected readonly CoreIdentDbContext Context;
    protected readonly ILogger<EfRefreshTokenStore> Logger;

    public EfRefreshTokenStore(CoreIdentDbContext context, ILogger<EfRefreshTokenStore> logger)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public virtual async Task StoreRefreshTokenAsync(CoreIdentRefreshToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(token);

        // Ensure HashedHandle is properly set if available
        if (!string.IsNullOrEmpty(token.HashedHandle) && string.IsNullOrEmpty(token.Handle))
        {
            token.Handle = token.HashedHandle; // Use HashedHandle as the primary key if Handle is empty
        }
        else if (string.IsNullOrEmpty(token.HashedHandle) && !string.IsNullOrEmpty(token.Handle))
        {
            token.HashedHandle = token.Handle; // Set HashedHandle for consistency if not already set
        }

        Context.RefreshTokens.Add(token);
        await Context.SaveChangesAsync(cancellationToken);

        Logger.LogDebug("Stored refresh token. Handle hash: {HashPrefix}", 
            token.Handle.Substring(0, Math.Min(6, token.Handle.Length)));
    }

    public virtual async Task<CoreIdentRefreshToken?> GetRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(tokenHandle);

        // Try to find by Handle (which is now expected to contain the hash) or HashedHandle
        var token = await Context.RefreshTokens.FirstOrDefaultAsync(
            rt => rt.Handle == tokenHandle || rt.HashedHandle == tokenHandle, 
            cancellationToken);
        
        if (token == null)
        {
            Logger.LogDebug("Refresh token not found with hash: {HashPrefix}", 
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        }
        
        return token;
    }

    public virtual async Task RemoveRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(tokenHandle);

        // Try to find by Handle or HashedHandle
        var token = await Context.RefreshTokens.FirstOrDefaultAsync(
            rt => rt.Handle == tokenHandle || rt.HashedHandle == tokenHandle, 
            cancellationToken);
            
        if (token != null)
        {
            // Mark as consumed (useful for replay detection with rotation)
            token.ConsumedTime = DateTime.UtcNow;
            Context.RefreshTokens.Update(token);

            await Context.SaveChangesAsync(cancellationToken);
            
            Logger.LogDebug("Marked refresh token as consumed. Hash: {HashPrefix}",
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        }
        else
        {
            Logger.LogDebug("No token found to consume with hash: {HashPrefix}",
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        }
        // If token not found, do nothing (idempotent) 
    }

    public virtual async Task RevokeTokenFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(familyId);

        // Find all active (non-consumed) tokens in the family
        var tokensToRevoke = await Context.RefreshTokens
            .Where(t => t.FamilyId == familyId && !t.ConsumedTime.HasValue)
            .ToListAsync(cancellationToken);

        // Mark all tokens as consumed
        foreach (var token in tokensToRevoke)
        {
            token.ConsumedTime = DateTime.UtcNow;
            Context.RefreshTokens.Update(token);
        }

        if (tokensToRevoke.Any())
        {
            await Context.SaveChangesAsync(cancellationToken);
            Logger.LogWarning("Revoked {Count} refresh tokens from family {FamilyId}", 
                tokensToRevoke.Count, familyId);
        }
    }

    public virtual async Task<IEnumerable<CoreIdentRefreshToken>> FindTokensBySubjectIdAsync(string subjectId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);

        return await Context.RefreshTokens
            .Where(t => t.SubjectId == subjectId)
            .ToListAsync(cancellationToken);
    }
} 