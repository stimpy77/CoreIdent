using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class EfRefreshTokenStoreTests : IDisposable
{
    private readonly CoreIdentDbContext _context;
    private readonly EfRefreshTokenStore _store;

    public EfRefreshTokenStoreTests()
    {
        var options = new DbContextOptionsBuilder<CoreIdentDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;

        _context = new CoreIdentDbContext(options);
        _context.Database.OpenConnection();
        _context.Database.EnsureCreated();

        _store = new EfRefreshTokenStore(_context);
    }

    public void Dispose()
    {
        _context.Database.CloseConnection();
        _context.Dispose();
    }

    private static CoreIdentRefreshToken CreateToken(string? handle = null, string? familyId = null) => new()
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

    private async Task SeedEntityAsync(RefreshTokenEntity entity)
    {
        _context.RefreshTokens.Add(entity);
        await _context.SaveChangesAsync();
    }

    [Fact]
    public async Task StoreAsync_GeneratesHandle_WhenHandleIsEmpty()
    {
        var token = CreateToken();

        var handle = await _store.StoreAsync(token);

        handle.ShouldNotBeNullOrWhiteSpace("should generate handle when not provided");
        token.Handle.ShouldBe(handle, "token handle should be updated");

        var entity = await _context.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(x => x.Handle == handle);
        entity.ShouldNotBeNull("entity should be persisted");
    }

    [Fact]
    public async Task GetAsync_ReturnsNull_WhenTokenDoesNotExist()
    {
        var result = await _store.GetAsync("nonexistent");

        result.ShouldBeNull("should return null for non-existent token");
    }

    [Fact]
    public async Task GetAsync_ReturnsToken_WhenTokenExists()
    {
        var token = CreateToken();
        var handle = await _store.StoreAsync(token);

        var result = await _store.GetAsync(handle);

        result.ShouldNotBeNull("should return stored token");
        result.SubjectId.ShouldBe(token.SubjectId, "subject id should match");
        result.Scopes.ShouldBe(token.Scopes, "scopes should round-trip");
    }

    [Fact]
    public async Task RevokeAsync_ReturnsFalse_WhenTokenDoesNotExist()
    {
        var result = await _store.RevokeAsync("nonexistent");

        result.ShouldBeFalse("should return false for non-existent token");
    }

    [Fact]
    public async Task RevokeAsync_RevokesToken()
    {
        var token = CreateToken();
        var handle = await _store.StoreAsync(token);

        var revoked = await _store.RevokeAsync(handle);

        revoked.ShouldBeTrue("should return true when token is revoked");

        var entity = await _context.RefreshTokens.AsNoTracking().FirstAsync(x => x.Handle == handle);
        entity.IsRevoked.ShouldBeTrue("entity should be marked revoked");
    }

    [Fact]
    public async Task RevokeFamilyAsync_RevokesAllTokensInFamily()
    {
        var familyId = "family-123";

        await SeedEntityAsync(new RefreshTokenEntity
        {
            Handle = "t1",
            SubjectId = "user-123",
            ClientId = "client-123",
            FamilyId = familyId,
            ScopesJson = JsonSerializer.Serialize(new[] { "openid" }),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            IsRevoked = false
        });

        await SeedEntityAsync(new RefreshTokenEntity
        {
            Handle = "t2",
            SubjectId = "user-123",
            ClientId = "client-123",
            FamilyId = familyId,
            ScopesJson = JsonSerializer.Serialize(new[] { "profile" }),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            IsRevoked = false
        });

        await SeedEntityAsync(new RefreshTokenEntity
        {
            Handle = "t3",
            SubjectId = "user-123",
            ClientId = "client-123",
            FamilyId = "other-family",
            ScopesJson = JsonSerializer.Serialize(new[] { "email" }),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            IsRevoked = false
        });

        await _store.RevokeFamilyAsync(familyId);

        var tokens = await _context.RefreshTokens.AsNoTracking().OrderBy(x => x.Handle).ToListAsync();
        tokens.Single(x => x.Handle == "t1").IsRevoked.ShouldBeTrue("t1 should be revoked");
        tokens.Single(x => x.Handle == "t2").IsRevoked.ShouldBeTrue("t2 should be revoked");
        tokens.Single(x => x.Handle == "t3").IsRevoked.ShouldBeFalse("t3 should not be revoked (different family)");
    }

    [Fact]
    public async Task ConsumeAsync_SetsConsumedAt_AndReturnsTrue_OnFirstConsume()
    {
        var token = CreateToken(handle: "consume-1");
        await _store.StoreAsync(token);

        var consumed = await _store.ConsumeAsync(token.Handle);

        consumed.ShouldBeTrue("should return true on first consume");

        var entity = await _context.RefreshTokens.AsNoTracking().FirstAsync(x => x.Handle == token.Handle);
        entity.ConsumedAt.ShouldNotBeNull("consumed timestamp should be set");
    }

    [Fact]
    public async Task ConsumeAsync_ReturnsFalse_WhenAlreadyConsumed()
    {
        var now = DateTime.UtcNow;
        await SeedEntityAsync(new RefreshTokenEntity
        {
            Handle = "already-consumed",
            SubjectId = "user-123",
            ClientId = "client-123",
            ScopesJson = "[]",
            CreatedAt = now,
            ExpiresAt = now.AddHours(1),
            ConsumedAt = now,
            IsRevoked = false
        });

        var consumed = await _store.ConsumeAsync("already-consumed");

        consumed.ShouldBeFalse("should return false if token is already consumed");
    }

    [Fact]
    public async Task CleanupExpiredAsync_RemovesExpiredTokensOnly()
    {
        var now = DateTime.UtcNow;

        await SeedEntityAsync(new RefreshTokenEntity
        {
            Handle = "expired",
            SubjectId = "user-123",
            ClientId = "client-123",
            ScopesJson = "[]",
            CreatedAt = now.AddHours(-2),
            ExpiresAt = now.AddSeconds(-1),
            IsRevoked = false
        });

        await SeedEntityAsync(new RefreshTokenEntity
        {
            Handle = "valid",
            SubjectId = "user-123",
            ClientId = "client-123",
            ScopesJson = "[]",
            CreatedAt = now,
            ExpiresAt = now.AddHours(1),
            IsRevoked = false
        });

        await _store.CleanupExpiredAsync();

        (await _context.RefreshTokens.AsNoTracking().AnyAsync(x => x.Handle == "expired")).ShouldBeFalse("expired token should be deleted");
        (await _context.RefreshTokens.AsNoTracking().AnyAsync(x => x.Handle == "valid")).ShouldBeTrue("valid token should remain");
    }
}
