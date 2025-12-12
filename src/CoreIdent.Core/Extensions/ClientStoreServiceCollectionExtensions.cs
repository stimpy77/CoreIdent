using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Extension methods for registering client store services.
/// </summary>
public static class ClientStoreServiceCollectionExtensions
{
    /// <summary>
    /// Adds the default client secret hasher to the service collection.
    /// </summary>
    public static IServiceCollection AddClientSecretHasher(this IServiceCollection services)
    {
        services.AddSingleton<IClientSecretHasher, DefaultClientSecretHasher>();
        return services;
    }

    /// <summary>
    /// Adds an in-memory client store to the service collection.
    /// </summary>
    public static IServiceCollection AddInMemoryClientStore(this IServiceCollection services)
    {
        services.AddClientSecretHasher();
        services.AddSingleton<InMemoryClientStore>();
        services.AddSingleton<IClientStore>(sp => sp.GetRequiredService<InMemoryClientStore>());
        return services;
    }

    /// <summary>
    /// Adds an in-memory client store with pre-seeded clients.
    /// </summary>
    public static IServiceCollection AddInMemoryClients(
        this IServiceCollection services,
        IEnumerable<CoreIdentClient> clients)
    {
        services.AddClientSecretHasher();
        services.AddSingleton<InMemoryClientStore>(sp =>
        {
            var hasher = sp.GetRequiredService<IClientSecretHasher>();
            var store = new InMemoryClientStore(hasher);
            store.SeedClients(clients);
            return store;
        });
        services.AddSingleton<IClientStore>(sp => sp.GetRequiredService<InMemoryClientStore>());
        return services;
    }

    /// <summary>
    /// Adds an in-memory client store with pre-seeded clients including plaintext secrets.
    /// </summary>
    public static IServiceCollection AddInMemoryClients(
        this IServiceCollection services,
        IEnumerable<(CoreIdentClient Client, string? PlaintextSecret)> clientsWithSecrets)
    {
        services.AddClientSecretHasher();
        services.AddSingleton<InMemoryClientStore>(sp =>
        {
            var hasher = sp.GetRequiredService<IClientSecretHasher>();
            var store = new InMemoryClientStore(hasher);
            foreach (var (client, secret) in clientsWithSecrets)
            {
                if (!string.IsNullOrWhiteSpace(secret))
                {
                    store.SeedClientWithSecret(client, secret);
                }
                else
                {
                    store.SeedClients([client]);
                }
            }
            return store;
        });
        services.AddSingleton<IClientStore>(sp => sp.GetRequiredService<InMemoryClientStore>());
        return services;
    }
}
