using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of IClientStore.
/// </summary>
public class EfClientStore : IClientStore
{
    protected readonly CoreIdentDbContext Context;

    public EfClientStore(CoreIdentDbContext context)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public virtual Task<CoreIdentClient?> FindClientByIdAsync(string clientId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(clientId);

        // Use Include to load related entities if needed immediately (e.g., secrets, scopes)
        // Using AsNoTracking() might improve performance if the client entity is not modified.
        return Context.Clients
            .Include(c => c.ClientSecrets) // Include secrets if often needed when loading client
            // .Include(c => c.AllowedScopes) // Can be large, might be better to load separately if needed
            .AsNoTracking() // Optional: Improve performance if client won't be updated
            .FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);
    }
} 