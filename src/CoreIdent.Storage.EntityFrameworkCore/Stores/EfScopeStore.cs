using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of IScopeStore.
/// </summary>
public class EfScopeStore : IScopeStore
{
    protected readonly CoreIdentDbContext Context;

    public EfScopeStore(CoreIdentDbContext context)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public virtual async Task<IEnumerable<CoreIdentScope>> FindScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scopeNames);

        var query = Context.Scopes
            .Include(s => s.UserClaims) // Include associated claims
            .AsNoTracking()
            .Where(s => scopeNames.Contains(s.Name));

        return await query.ToListAsync(cancellationToken);
    }

    public virtual async Task<IEnumerable<CoreIdentScope>> GetAllScopesAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return await Context.Scopes
            .Include(s => s.UserClaims)
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }
} 