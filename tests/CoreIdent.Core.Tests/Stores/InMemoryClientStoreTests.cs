using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores.InMemory;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class InMemoryClientStoreTests
{
    private readonly IClientSecretHasher _hasher = new DefaultClientSecretHasher();

    private InMemoryClientStore CreateStore() => new(_hasher);

    private static CoreIdentClient CreateTestClient(string clientId = "test-client") => new()
    {
        ClientId = clientId,
        ClientName = "Test Client",
        ClientType = ClientType.Confidential,
        AllowedScopes = ["openid", "profile"],
        AllowedGrantTypes = ["client_credentials"],
        Enabled = true,
        CreatedAt = DateTime.UtcNow
    };

    [Fact]
    public async Task FindByClientIdAsync_ReturnsNull_WhenClientDoesNotExist()
    {
        var store = CreateStore();

        var result = await store.FindByClientIdAsync("nonexistent");

        result.ShouldBeNull("should return null for non-existent client");
    }

    [Fact]
    public async Task CreateAsync_And_FindByClientIdAsync_WorkCorrectly()
    {
        var store = CreateStore();
        var client = CreateTestClient();

        await store.CreateAsync(client);
        var result = await store.FindByClientIdAsync(client.ClientId);

        result.ShouldNotBeNull("should find created client");
        result.ClientId.ShouldBe(client.ClientId, "client ID should match");
        result.ClientName.ShouldBe(client.ClientName, "client name should match");
    }

    [Fact]
    public async Task CreateAsync_ThrowsException_WhenClientAlreadyExists()
    {
        var store = CreateStore();
        var client = CreateTestClient();

        await store.CreateAsync(client);

        await Should.ThrowAsync<InvalidOperationException>(
            () => store.CreateAsync(client),
            "should throw when creating duplicate client");
    }

    [Fact]
    public async Task UpdateAsync_UpdatesClient()
    {
        var store = CreateStore();
        var client = CreateTestClient();
        await store.CreateAsync(client);

        client.ClientName = "Updated Name";
        client.UpdatedAt = DateTime.UtcNow;
        await store.UpdateAsync(client);

        var result = await store.FindByClientIdAsync(client.ClientId);
        result.ShouldNotBeNull();
        result.ClientName.ShouldBe("Updated Name", "client name should be updated");
    }

    [Fact]
    public async Task UpdateAsync_ThrowsException_WhenClientDoesNotExist()
    {
        var store = CreateStore();
        var client = CreateTestClient();

        await Should.ThrowAsync<InvalidOperationException>(
            () => store.UpdateAsync(client),
            "should throw when updating non-existent client");
    }

    [Fact]
    public async Task DeleteAsync_RemovesClient()
    {
        var store = CreateStore();
        var client = CreateTestClient();
        await store.CreateAsync(client);

        await store.DeleteAsync(client.ClientId);

        var result = await store.FindByClientIdAsync(client.ClientId);
        result.ShouldBeNull("client should be deleted");
    }

    [Fact]
    public async Task DeleteAsync_DoesNotThrow_WhenClientDoesNotExist()
    {
        var store = CreateStore();

        await Should.NotThrowAsync(
            () => store.DeleteAsync("nonexistent"),
            "should not throw when deleting non-existent client");
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsTrue_ForValidSecret()
    {
        var store = CreateStore();
        var client = CreateTestClient();
        const string secret = "super-secret-123";

        store.SeedClientWithSecret(client, secret);

        var result = await store.ValidateClientSecretAsync(client.ClientId, secret);

        result.ShouldBeTrue("should validate correct secret");
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsFalse_ForInvalidSecret()
    {
        var store = CreateStore();
        var client = CreateTestClient();
        const string secret = "super-secret-123";

        store.SeedClientWithSecret(client, secret);

        var result = await store.ValidateClientSecretAsync(client.ClientId, "wrong-secret");

        result.ShouldBeFalse("should reject incorrect secret");
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsFalse_ForNonExistentClient()
    {
        var store = CreateStore();

        var result = await store.ValidateClientSecretAsync("nonexistent", "any-secret");

        result.ShouldBeFalse("should return false for non-existent client");
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsTrue_ForPublicClient()
    {
        var store = CreateStore();
        var client = CreateTestClient();
        client.ClientType = ClientType.Public;
        client.ClientSecretHash = null;

        await store.CreateAsync(client);

        var result = await store.ValidateClientSecretAsync(client.ClientId, "any-value");

        result.ShouldBeTrue("public clients should not require secret validation");
    }

    [Fact]
    public async Task SeedClients_AddsMultipleClients()
    {
        var store = CreateStore();
        var clients = new[]
        {
            CreateTestClient("client-1"),
            CreateTestClient("client-2"),
            CreateTestClient("client-3")
        };

        store.SeedClients(clients);

        (await store.FindByClientIdAsync("client-1")).ShouldNotBeNull("client-1 should be seeded");
        (await store.FindByClientIdAsync("client-2")).ShouldNotBeNull("client-2 should be seeded");
        (await store.FindByClientIdAsync("client-3")).ShouldNotBeNull("client-3 should be seeded");
    }
}
