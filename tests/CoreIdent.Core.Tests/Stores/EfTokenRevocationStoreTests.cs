using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class EfTokenRevocationStoreTests : IDisposable
{
    private readonly CoreIdentDbContext _context;
    private readonly MutableTimeProvider _timeProvider;
    private readonly EfTokenRevocationStore _store;

    public EfTokenRevocationStoreTests()
    {
        var options = new DbContextOptionsBuilder<CoreIdentDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;

        _context = new CoreIdentDbContext(options);
        _context.Database.OpenConnection();
        _context.Database.EnsureCreated();

        _timeProvider = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        _store = new EfTokenRevocationStore(_context, _timeProvider);
    }

    public void Dispose()
    {
        _context.Database.CloseConnection();
        _context.Dispose();
    }

    [Fact]
    public async Task RevokeTokenAsync_stores_token_and_IsRevokedAsync_returns_true()
    {
        var jti = "jti-1";
        var expiry = _timeProvider.GetUtcNow().AddMinutes(10).UtcDateTime;

        await _store.RevokeTokenAsync(jti, tokenType: "access_token", expiry: expiry);

        var isRevoked = await _store.IsRevokedAsync(jti);
        isRevoked.ShouldBeTrue("Token should be revoked after storing revocation.");
    }

    [Fact]
    public async Task IsRevokedAsync_returns_false_for_non_revoked_token()
    {
        var isRevoked = await _store.IsRevokedAsync("nonexistent-jti");

        isRevoked.ShouldBeFalse("Non-revoked token should return false.");
    }

    [Fact]
    public async Task IsRevokedAsync_returns_false_after_token_expires()
    {
        var jti = "jti-expiring";
        var expiry = _timeProvider.GetUtcNow().AddMinutes(5).UtcDateTime;

        await _store.RevokeTokenAsync(jti, tokenType: "access_token", expiry: expiry);

        var beforeExpiry = await _store.IsRevokedAsync(jti);
        beforeExpiry.ShouldBeTrue("Token should be revoked before expiry.");

        _timeProvider.Advance(TimeSpan.FromMinutes(10));

        var afterExpiry = await _store.IsRevokedAsync(jti);
        afterExpiry.ShouldBeFalse("Token should not be considered revoked after its expiry time passes.");
    }

    [Fact]
    public async Task RevokeTokenAsync_does_not_store_already_expired_token()
    {
        var jti = "jti-already-expired";
        var expiry = _timeProvider.GetUtcNow().AddSeconds(-1).UtcDateTime;

        await _store.RevokeTokenAsync(jti, tokenType: "access_token", expiry: expiry);

        var entity = await _context.RevokedTokens.AsNoTracking().FirstOrDefaultAsync(x => x.Jti == jti);
        entity.ShouldBeNull("Already expired token should not be stored.");
    }

    [Fact]
    public async Task RevokeTokenAsync_updates_existing_revocation()
    {
        var jti = "jti-update";
        var expiry1 = _timeProvider.GetUtcNow().AddMinutes(5).UtcDateTime;
        var expiry2 = _timeProvider.GetUtcNow().AddMinutes(15).UtcDateTime;

        await _store.RevokeTokenAsync(jti, tokenType: "access_token", expiry: expiry1);
        await _store.RevokeTokenAsync(jti, tokenType: "refresh_token", expiry: expiry2);

        var entity = await _context.RevokedTokens.AsNoTracking().SingleAsync(x => x.Jti == jti);
        entity.TokenType.ShouldBe("refresh_token", "Token type should be updated.");
        entity.ExpiresAtUtc.ShouldBe(expiry2.ToUniversalTime(), "Expiry should be updated.");
    }

    [Fact]
    public async Task CleanupExpiredAsync_removes_only_expired_entries()
    {
        var expiringJti = "jti-expiring";
        var longLivedJti = "jti-long-lived";

        await _store.RevokeTokenAsync(expiringJti, tokenType: "access_token", expiry: _timeProvider.GetUtcNow().AddSeconds(1).UtcDateTime);
        await _store.RevokeTokenAsync(longLivedJti, tokenType: "access_token", expiry: _timeProvider.GetUtcNow().AddHours(1).UtcDateTime);

        _timeProvider.Advance(TimeSpan.FromSeconds(5));

        await _store.CleanupExpiredAsync();

        var expiringExists = await _context.RevokedTokens.AsNoTracking().AnyAsync(x => x.Jti == expiringJti);
        expiringExists.ShouldBeFalse("Expired revoked token entry should be cleaned up.");

        var longLivedExists = await _context.RevokedTokens.AsNoTracking().AnyAsync(x => x.Jti == longLivedJti);
        longLivedExists.ShouldBeTrue("Non-expired revoked token entry should not be removed by cleanup.");
    }

    [Fact]
    public async Task RevokeTokenAsync_throws_when_jti_is_null_or_empty()
    {
        await Should.ThrowAsync<ArgumentException>(
            () => _store.RevokeTokenAsync("", tokenType: "access_token", expiry: DateTime.UtcNow.AddMinutes(5)),
            "Should throw when JTI is empty.");

        await Should.ThrowAsync<ArgumentException>(
            () => _store.RevokeTokenAsync(null!, tokenType: "access_token", expiry: DateTime.UtcNow.AddMinutes(5)),
            "Should throw when JTI is null.");
    }

    [Fact]
    public async Task RevokeTokenAsync_throws_when_tokenType_is_null_or_empty()
    {
        await Should.ThrowAsync<ArgumentException>(
            () => _store.RevokeTokenAsync("jti", tokenType: "", expiry: DateTime.UtcNow.AddMinutes(5)),
            "Should throw when token type is empty.");

        await Should.ThrowAsync<ArgumentException>(
            () => _store.RevokeTokenAsync("jti", tokenType: null!, expiry: DateTime.UtcNow.AddMinutes(5)),
            "Should throw when token type is null.");
    }

    [Fact]
    public async Task IsRevokedAsync_returns_false_for_null_or_empty_jti()
    {
        var resultEmpty = await _store.IsRevokedAsync("");
        resultEmpty.ShouldBeFalse("Should return false for empty JTI.");

        var resultNull = await _store.IsRevokedAsync(null!);
        resultNull.ShouldBeFalse("Should return false for null JTI.");
    }

    private sealed class MutableTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow;

        public MutableTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public void Advance(TimeSpan delta)
        {
            _utcNow = _utcNow.Add(delta);
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }
}
