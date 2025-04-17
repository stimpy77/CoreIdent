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
    // Revert to injecting DbContext directly
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

        Logger.LogDebug("Attempting to add RefreshToken to context. Handle: {Handle}, HashedHandle: {HashedHandle}, SubjectId: {SubjectId}, ClientId: {ClientId}, FamilyId: {FamilyId}",
            token.Handle, token.HashedHandle, token.SubjectId, token.ClientId, token.FamilyId);

        Context.RefreshTokens.Add(token);
        
        try
        {
            Logger.LogInformation("Calling SaveChangesAsync for RefreshToken Handle: {Handle}", token.Handle);
            var changes = await Context.SaveChangesAsync(cancellationToken); 
            Logger.LogInformation("SaveChangesAsync SUCCESS for RefreshToken Handle: {Handle}. Changes saved: {Changes}", token.Handle, changes);
        }
        catch(Exception ex)
        {
            Logger.LogError(ex, "SaveChangesAsync FAILED for RefreshToken Handle: {Handle}. Entity State: {State}", 
                token.Handle, Context.Entry(token).State);
            // Re-throw the exception so the service layer knows storage failed.
            throw; 
        }

        Logger.LogDebug("Successfully stored refresh token. Handle: {HandlePrefix}", 
            token.Handle.Substring(0, Math.Min(6, token.Handle.Length)));
    }

    public virtual async Task<CoreIdentRefreshToken?> GetRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(tokenHandle);

        // Use injected context
        var token = await Context.RefreshTokens.FirstOrDefaultAsync(
            rt => rt.Handle == tokenHandle, 
            cancellationToken);
        
        if (token == null)
        {
            // Log using raw handle prefix for consistency
            Logger.LogDebug("Refresh token not found with handle: {HandlePrefix}", 
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        }
        
        return token;
    }

    public virtual async Task RemoveRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(tokenHandle);

        // Use injected context
        var token = await Context.RefreshTokens.FirstOrDefaultAsync(
            rt => rt.Handle == tokenHandle, 
            cancellationToken);
            
        if (token != null)
        {
            // Mark as consumed 
            token.ConsumedTime = DateTime.UtcNow;
            Context.RefreshTokens.Update(token);

            await Context.SaveChangesAsync(cancellationToken);
            
            // Log using raw handle prefix
            Logger.LogDebug("Marked refresh token as consumed. Handle: {HandlePrefix}",
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        }
        else
        {
             // Log using raw handle prefix
            Logger.LogDebug("No token found to consume with handle: {HandlePrefix}",
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        }
        // If token not found, do nothing (idempotent) 
    }

    public virtual async Task RevokeTokenFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(familyId);

        // Use injected context
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

        // Use injected context
        return await Context.RefreshTokens
            .Where(t => t.SubjectId == subjectId)
            .ToListAsync(cancellationToken);
    }
} 