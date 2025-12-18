using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public sealed class ClientStoreServiceCollectionExtensionsTests
{
    [Fact]
    public void AddClientSecretHasher_registers_default_hasher()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddClientSecretHasher();

        // Assert
        services.ShouldContainSingleton<IClientSecretHasher, DefaultClientSecretHasher>();
    }

    [Fact]
    public void AddInMemoryClientStore_registers_required_services()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddInMemoryClientStore();

        // Assert
        services.ShouldContainSingleton<IClientSecretHasher, DefaultClientSecretHasher>();
        services.ShouldContainSingleton<InMemoryClientStore>();
        services.ShouldContainSingleton<IClientStore, InMemoryClientStore>();
    }

    [Fact]
    public async Task AddInMemoryClients_with_clients_registers_and_seeds_store()
    {
        // Arrange
        var services = new ServiceCollection();
        var clients = new[]
        {
            new CoreIdentClient
            {
                ClientId = "test-client-1",
                ClientName = "Test Client 1",
                RedirectUris = ["https://client1.example/callback"]
            },
            new CoreIdentClient
            {
                ClientId = "test-client-2", 
                ClientName = "Test Client 2",
                RedirectUris = ["https://client2.example/callback"]
            }
        };

        // Act
        services.AddInMemoryClients(clients);

        // Assert
        services.ShouldContainSingleton<IClientSecretHasher, DefaultClientSecretHasher>();
        services.ShouldContainSingleton<InMemoryClientStore>();
        services.ShouldContainSingleton<IClientStore, InMemoryClientStore>();

        // Verify seeding
        var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<IClientStore>();
        
        var client1 = await store.FindByClientIdAsync("test-client-1");
        client1.ShouldNotBeNull();
        client1.ClientName.ShouldBe("Test Client 1");

        var client2 = await store.FindByClientIdAsync("test-client-2");
        client2.ShouldNotBeNull();
        client2.ClientName.ShouldBe("Test Client 2");
    }

    [Fact]
    public async Task AddInMemoryClients_with_clients_and_seeds_registers_and_seeds_with_secrets()
    {
        // Arrange
        var services = new ServiceCollection();
        var clientsWithSecrets = new[]
        {
            (
                new CoreIdentClient
                {
                    ClientId = "secret-client",
                    ClientName = "Secret Client",
                    RedirectUris = ["https://secret.example/callback"]
                },
                "super-secret-password"
            ),
            (
                new CoreIdentClient
                {
                    ClientId = "public-client",
                    ClientName = "Public Client", 
                    RedirectUris = ["https://public.example/callback"]
                },
                null // No secret
            )
        };

        // Act
        services.AddInMemoryClients(clientsWithSecrets);

        // Assert
        services.ShouldContainSingleton<IClientSecretHasher, DefaultClientSecretHasher>();
        services.ShouldContainSingleton<InMemoryClientStore>();
        services.ShouldContainSingleton<IClientStore, InMemoryClientStore>();

        // Verify seeding
        var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<IClientStore>();
        
        var secretClient = await store.FindByClientIdAsync("secret-client");
        secretClient.ShouldNotBeNull();
        secretClient.ClientName.ShouldBe("Secret Client");
        secretClient.ClientSecretHash.ShouldNotBeNull();

        var publicClient = await store.FindByClientIdAsync("public-client");
        publicClient.ShouldNotBeNull();
        publicClient.ClientName.ShouldBe("Public Client");
        publicClient.ClientSecretHash.ShouldBeNull();
    }

    [Fact]
    public void AddInMemoryClients_with_empty_collection_registers_store()
    {
        // Arrange
        var services = new ServiceCollection();
        var emptyClients = Array.Empty<CoreIdentClient>();

        // Act
        services.AddInMemoryClients(emptyClients);

        // Assert
        services.ShouldContainSingleton<IClientSecretHasher, DefaultClientSecretHasher>();
        services.ShouldContainSingleton<InMemoryClientStore>();
        services.ShouldContainSingleton<IClientStore, InMemoryClientStore>();
    }

    [Fact]
    public void AddInMemoryClients_with_empty_secrets_collection_registers_store()
    {
        // Arrange
        var services = new ServiceCollection();
        var emptyClientsWithSecrets = Array.Empty<(CoreIdentClient Client, string? PlaintextSecret)>();

        // Act
        services.AddInMemoryClients(emptyClientsWithSecrets);

        // Assert
        services.ShouldContainSingleton<IClientSecretHasher, DefaultClientSecretHasher>();
        services.ShouldContainSingleton<InMemoryClientStore>();
        services.ShouldContainSingleton<IClientStore, InMemoryClientStore>();
    }
}
