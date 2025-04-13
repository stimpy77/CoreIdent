using CoreIdent.Core.Models;
using CoreIdent.Core.Tests.Infrastructure;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Shouldly;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using System.Threading;
using System;

namespace CoreIdent.Core.Tests.Stores;

public class EfClientStoreTests : SqliteInMemoryTestBase
{
    private readonly EfClientStore _clientStore;

    public EfClientStoreTests()
    {
        _clientStore = new EfClientStore(DbContext);
    }

    private async Task SeedClientAsync(CoreIdentClient client)
    {
        DbContext.Clients.Add(client);
        await DbContext.SaveChangesAsync(CancellationToken.None);
    }

    [Fact]
    public async Task FindClientByIdAsync_ShouldReturnClientWithSecrets_WhenExists()
    {
        // Arrange
        var clientId = "test_client_1";
        var client = new CoreIdentClient
        {
            ClientId = clientId,
            ClientName = "Test Client 1",
            AllowedGrantTypes = new List<string> { "client_credentials" },
            ClientSecrets = new List<CoreIdentClientSecret>
            {
                new CoreIdentClientSecret { Value = "secret1", Type = "SharedSecret" },
                new CoreIdentClientSecret { Value = "secret2_expired", Expiration = DateTime.UtcNow.AddDays(-1) }
            }
        };
        await SeedClientAsync(client);

        // Act
        // Note: FindClientByIdAsync uses AsNoTracking and Includes secrets by default
        var foundClient = await _clientStore.FindClientByIdAsync(clientId, CancellationToken.None);

        // Assert
        foundClient.ShouldNotBeNull();
        foundClient.ClientId.ShouldBe(clientId);
        foundClient.ClientName.ShouldBe("Test Client 1");
        foundClient.AllowedGrantTypes.ShouldContain("client_credentials");

        foundClient.ClientSecrets.ShouldNotBeNull();
        foundClient.ClientSecrets.Count.ShouldBe(2);
        foundClient.ClientSecrets.ShouldContain(s => s.Value == "secret1");
        foundClient.ClientSecrets.ShouldContain(s => s.Value == "secret2_expired");
    }

    [Fact]
    public async Task FindClientByIdAsync_ShouldReturnNull_WhenNotExists()
    {
        // Arrange
        var nonExistentClientId = "does_not_exist";

        // Act
        var foundClient = await _clientStore.FindClientByIdAsync(nonExistentClientId, CancellationToken.None);

        // Assert
        foundClient.ShouldBeNull();
    }

    // Add more tests? e.g., Find client without secrets, testing value conversions if complex types were used.
} 