using CoreIdent.Core.Models;
using CoreIdent.Core.Stores.InMemory;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class InMemoryRefreshTokenStoreTests
{
    private static CoreIdentRefreshToken CreateTestToken(string? handle = null, string? familyId = null) => new()
    {
        Handle = handle ?? string.Empty,
        SubjectId = "user-123",
        ClientId = "client-123",
        FamilyId = familyId,
        Scopes = ["openid", "profile"],
        CreatedAt = DateTime.UtcNow,
        ExpiresAt = DateTime.UtcNow.AddHours(1),
        ConsumedAt = null,
        IsRevoked = false
    };

    [Fact]
    public async Task StoreAsync_GeneratesHandle_WhenHandleIsEmpty()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = CreateTestToken();

        var handle = await store.StoreAsync(token);

        handle.ShouldNotBeNullOrWhiteSpace("should generate a handle when none provided");
        token.Handle.ShouldBe(handle, "token handle should be updated");
    }

    [Fact]
    public async Task StoreAsync_UsesProvidedHandle()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = CreateTestToken(handle: "my-custom-handle");

        var handle = await store.StoreAsync(token);

        handle.ShouldBe("my-custom-handle", "should use provided handle");
    }

    [Fact]
    public async Task GetAsync_ReturnsNull_WhenTokenDoesNotExist()
    {
        var store = new InMemoryRefreshTokenStore();

        var result = await store.GetAsync("nonexistent");

        result.ShouldBeNull("should return null for non-existent token");
    }

    [Fact]
    public async Task GetAsync_ReturnsToken_WhenTokenExists()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = CreateTestToken();
        var handle = await store.StoreAsync(token);

        var result = await store.GetAsync(handle);

        result.ShouldNotBeNull("should find stored token");
        result.SubjectId.ShouldBe(token.SubjectId, "subject ID should match");
        result.ClientId.ShouldBe(token.ClientId, "client ID should match");
    }

    [Fact]
    public async Task RevokeAsync_ReturnsFalse_WhenTokenDoesNotExist()
    {
        var store = new InMemoryRefreshTokenStore();

        var result = await store.RevokeAsync("nonexistent");

        result.ShouldBeFalse("should return false for non-existent token");
    }

    [Fact]
    public async Task RevokeAsync_RevokesToken()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = CreateTestToken();
        var handle = await store.StoreAsync(token);

        var result = await store.RevokeAsync(handle);

        result.ShouldBeTrue("should return true when token is revoked");
        var retrieved = await store.GetAsync(handle);
        retrieved.ShouldNotBeNull();
        retrieved.IsRevoked.ShouldBeTrue("token should be marked as revoked");
    }

    [Fact]
    public async Task RevokeFamilyAsync_RevokesAllTokensInFamily()
    {
        var store = new InMemoryRefreshTokenStore();
        var familyId = "family-123";
        var token1 = CreateTestToken(familyId: familyId);
        var token2 = CreateTestToken(familyId: familyId);
        var token3 = CreateTestToken(familyId: "other-family");

        var handle1 = await store.StoreAsync(token1);
        var handle2 = await store.StoreAsync(token2);
        var handle3 = await store.StoreAsync(token3);

        await store.RevokeFamilyAsync(familyId);

        (await store.GetAsync(handle1))!.IsRevoked.ShouldBeTrue("token1 should be revoked");
        (await store.GetAsync(handle2))!.IsRevoked.ShouldBeTrue("token2 should be revoked");
        (await store.GetAsync(handle3))!.IsRevoked.ShouldBeFalse("token3 should not be revoked (different family)");
    }

    [Fact]
    public async Task ConsumeAsync_ReturnsFalse_WhenTokenDoesNotExist()
    {
        var store = new InMemoryRefreshTokenStore();

        var result = await store.ConsumeAsync("nonexistent");

        result.ShouldBeFalse("should return false for non-existent token");
    }

    [Fact]
    public async Task ConsumeAsync_ConsumesToken()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = CreateTestToken();
        var handle = await store.StoreAsync(token);

        var result = await store.ConsumeAsync(handle);

        result.ShouldBeTrue("should return true when token is consumed");
        var retrieved = await store.GetAsync(handle);
        retrieved.ShouldNotBeNull();
        retrieved.ConsumedAt.ShouldNotBeNull("token should have consumed timestamp");
    }

    [Fact]
    public async Task ConsumeAsync_ReturnsFalse_WhenTokenAlreadyConsumed()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = CreateTestToken();
        var handle = await store.StoreAsync(token);

        await store.ConsumeAsync(handle);
        var result = await store.ConsumeAsync(handle);

        result.ShouldBeFalse("should return false when token is already consumed");
    }

    [Fact]
    public async Task CleanupExpiredAsync_RemovesExpiredTokens()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryRefreshTokenStore(time);

        var expiredToken = CreateTestToken();
        expiredToken.ExpiresAt = time.GetUtcNow().AddSeconds(-1).UtcDateTime;

        var validToken = CreateTestToken();
        validToken.ExpiresAt = time.GetUtcNow().AddHours(1).UtcDateTime;

        var expiredHandle = await store.StoreAsync(expiredToken);
        var validHandle = await store.StoreAsync(validToken);

        await store.CleanupExpiredAsync();

        (await store.GetAsync(expiredHandle)).ShouldBeNull("expired token should be removed");
        (await store.GetAsync(validHandle)).ShouldNotBeNull("valid token should remain");
    }

}
