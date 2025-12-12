using CoreIdent.Core.Stores.InMemory;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Stores;

public class InMemoryTokenRevocationStoreTests
{
    [Fact]
    public async Task RevokeTokenAsync_stores_and_IsRevokedAsync_returns_true_until_expiry()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryTokenRevocationStore(time);

        var jti = "jti-1";

        var before = await store.IsRevokedAsync(jti);
        before.ShouldBeFalse("Token should not be revoked before it is added.");

        await store.RevokeTokenAsync(jti, tokenType: "access_token", expiry: time.GetUtcNow().AddMinutes(10).UtcDateTime);

        var active = await store.IsRevokedAsync(jti);
        active.ShouldBeTrue("Token should be revoked after revocation is stored.");

        time.Advance(TimeSpan.FromMinutes(11));

        var afterExpiry = await store.IsRevokedAsync(jti);
        afterExpiry.ShouldBeFalse("Token should not be considered revoked after its expiry time passes.");
    }

    [Fact]
    public async Task CleanupExpiredAsync_removes_only_expired_entries()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryTokenRevocationStore(time);

        await store.RevokeTokenAsync("jti-expiring", tokenType: "access_token", expiry: time.GetUtcNow().AddSeconds(1).UtcDateTime);
        await store.RevokeTokenAsync("jti-long", tokenType: "access_token", expiry: time.GetUtcNow().AddHours(1).UtcDateTime);

        time.Advance(TimeSpan.FromSeconds(5));

        await store.CleanupExpiredAsync();

        var expiring = await store.IsRevokedAsync("jti-expiring");
        expiring.ShouldBeFalse("Expired revoked token entry should be cleaned up.");

        var longLived = await store.IsRevokedAsync("jti-long");
        longLived.ShouldBeTrue("Non-expired revoked token entry should not be removed by cleanup.");
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
