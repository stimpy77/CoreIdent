using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class EfClientStoreTests : IDisposable
{
    private readonly CoreIdentDbContext _context;
    private readonly EfClientStore _store;
    private readonly IClientSecretHasher _hasher = new DefaultClientSecretHasher();

    public EfClientStoreTests()
    {
        var options = new DbContextOptionsBuilder<CoreIdentDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;

        _context = new CoreIdentDbContext(options);
        _context.Database.OpenConnection();
        _context.Database.EnsureCreated();

        _store = new EfClientStore(_context, _hasher);
    }

    public void Dispose()
    {
        _context.Database.CloseConnection();
        _context.Dispose();
    }

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
        var result = await _store.FindByClientIdAsync("nonexistent");

        result.ShouldBeNull("should return null for non-existent client");
    }

    [Fact]
    public async Task CreateAsync_And_FindByClientIdAsync_WorkCorrectly()
    {
        var client = CreateTestClient();

        await _store.CreateAsync(client);
        var result = await _store.FindByClientIdAsync(client.ClientId);

        result.ShouldNotBeNull("should find created client");
        result.ClientId.ShouldBe(client.ClientId, "client ID should match");
        result.ClientName.ShouldBe(client.ClientName, "client name should match");
        result.AllowedScopes.ShouldBe(client.AllowedScopes, "scopes should match");
        result.AllowedGrantTypes.ShouldBe(client.AllowedGrantTypes, "grant types should match");
    }

    [Fact]
    public async Task UpdateAsync_UpdatesClient()
    {
        var client = CreateTestClient();
        await _store.CreateAsync(client);

        client.ClientName = "Updated Name";
        client.UpdatedAt = DateTime.UtcNow;
        await _store.UpdateAsync(client);

        var result = await _store.FindByClientIdAsync(client.ClientId);
        result.ShouldNotBeNull();
        result.ClientName.ShouldBe("Updated Name", "client name should be updated");
    }

    [Fact]
    public async Task UpdateAsync_ThrowsException_WhenClientDoesNotExist()
    {
        var client = CreateTestClient();

        await Should.ThrowAsync<InvalidOperationException>(
            () => _store.UpdateAsync(client),
            "should throw when updating non-existent client");
    }

    [Fact]
    public async Task DeleteAsync_RemovesClient()
    {
        var client = CreateTestClient();
        await _store.CreateAsync(client);

        await _store.DeleteAsync(client.ClientId);

        var result = await _store.FindByClientIdAsync(client.ClientId);
        result.ShouldBeNull("client should be deleted");
    }

    [Fact]
    public async Task DeleteAsync_DoesNotThrow_WhenClientDoesNotExist()
    {
        await Should.NotThrowAsync(
            () => _store.DeleteAsync("nonexistent"),
            "should not throw when deleting non-existent client");
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsTrue_ForValidSecret()
    {
        var client = CreateTestClient();
        const string secret = "super-secret-123";
        client.ClientSecretHash = _hasher.HashSecret(secret);

        await _store.CreateAsync(client);

        var result = await _store.ValidateClientSecretAsync(client.ClientId, secret);

        result.ShouldBeTrue("should validate correct secret");
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsFalse_ForInvalidSecret()
    {
        var client = CreateTestClient();
        const string secret = "super-secret-123";
        client.ClientSecretHash = _hasher.HashSecret(secret);

        await _store.CreateAsync(client);

        var result = await _store.ValidateClientSecretAsync(client.ClientId, "wrong-secret");

        result.ShouldBeFalse("should reject incorrect secret");
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsFalse_ForNonExistentClient()
    {
        var result = await _store.ValidateClientSecretAsync("nonexistent", "any-secret");

        result.ShouldBeFalse("should return false for non-existent client");
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsTrue_ForPublicClient()
    {
        var client = CreateTestClient();
        client.ClientType = ClientType.Public;
        client.ClientSecretHash = null;

        await _store.CreateAsync(client);

        var result = await _store.ValidateClientSecretAsync(client.ClientId, "any-value");

        result.ShouldBeTrue("public clients should not require secret validation");
    }

    [Fact]
    public async Task CreateAsync_PersistsCollectionProperties()
    {
        var client = CreateTestClient();
        client.RedirectUris = ["https://example.com/callback", "https://example.com/callback2"];
        client.PostLogoutRedirectUris = ["https://example.com/logout"];
        client.AllowedScopes = ["openid", "profile", "email"];
        client.AllowedGrantTypes = ["authorization_code", "refresh_token"];

        await _store.CreateAsync(client);
        var result = await _store.FindByClientIdAsync(client.ClientId);

        result.ShouldNotBeNull();
        result.RedirectUris.ShouldBe(client.RedirectUris, "redirect URIs should be persisted");
        result.PostLogoutRedirectUris.ShouldBe(client.PostLogoutRedirectUris, "post-logout URIs should be persisted");
        result.AllowedScopes.ShouldBe(client.AllowedScopes, "scopes should be persisted");
        result.AllowedGrantTypes.ShouldBe(client.AllowedGrantTypes, "grant types should be persisted");
    }
}
