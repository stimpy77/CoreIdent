using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of IRefreshTokenStore.
/// </summary>
public class EfRefreshTokenStore : IRefreshTokenStore
{
    protected readonly CoreIdentDbContext Context;

    public EfRefreshTokenStore(CoreIdentDbContext context)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public virtual async Task StoreRefreshTokenAsync(CoreIdentRefreshToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(token);

        Context.RefreshTokens.Add(token);
        await Context.SaveChangesAsync(cancellationToken);
    }

    public virtual Task<CoreIdentRefreshToken?> GetRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(tokenHandle);

        return Context.RefreshTokens.FindAsync(new object[] { tokenHandle }, cancellationToken).AsTask();
    }

    public virtual async Task RemoveRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(tokenHandle);

        var token = await Context.RefreshTokens.FindAsync(new object[] { tokenHandle }, cancellationToken);
        if (token != null)
        {
            // Option 1: Physically remove
            // Context.RefreshTokens.Remove(token);

            // Option 2: Mark as consumed (useful for replay detection with rotation)
            token.ConsumedTime = DateTime.UtcNow;
            Context.RefreshTokens.Update(token);

            await Context.SaveChangesAsync(cancellationToken);
        }
        // If token not found, do nothing (idempotent) 
    }
} 