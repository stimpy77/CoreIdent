using CoreIdent.Core.Models;
using CoreIdent.Core.Stores.InMemory;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Stores;

public class InMemoryAuthorizationCodeStoreTests
{
    [Fact]
    public async Task CreateAsync_generates_handle_and_sets_created_at_when_missing()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryAuthorizationCodeStore(time);

        var code = new CoreIdentAuthorizationCode
        {
            Handle = string.Empty,
            ClientId = "client",
            SubjectId = "sub",
            RedirectUri = "https://client.example/cb",
            Scopes = ["openid"],
            CreatedAt = default,
            ExpiresAt = time.GetUtcNow().AddMinutes(5).UtcDateTime,
            CodeChallenge = "cc",
            CodeChallengeMethod = "S256"
        };

        await store.CreateAsync(code);

        code.Handle.ShouldNotBeNullOrWhiteSpace("CreateAsync should generate a handle when empty.");
        code.CreatedAt.ShouldBe(time.GetUtcNow().UtcDateTime, "CreateAsync should set CreatedAt when default.");
    }

    [Fact]
    public async Task CreateAsync_throws_when_handle_already_exists()
    {
        var store = new InMemoryAuthorizationCodeStore();

        var code1 = new CoreIdentAuthorizationCode
        {
            Handle = "h1",
            ClientId = "client",
            SubjectId = "sub",
            RedirectUri = "https://client.example/cb",
            Scopes = ["openid"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            CodeChallenge = "cc",
            CodeChallengeMethod = "S256"
        };

        var code2 = new CoreIdentAuthorizationCode
        {
            Handle = "h1",
            ClientId = "client",
            SubjectId = "sub",
            RedirectUri = "https://client.example/cb",
            Scopes = ["openid"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            CodeChallenge = "cc",
            CodeChallengeMethod = "S256"
        };

        await store.CreateAsync(code1);

        await Should.ThrowAsync<InvalidOperationException>(async () => await store.CreateAsync(code2), "Duplicate handle should throw.");
    }

    [Fact]
    public async Task GetAsync_returns_null_for_missing_handle_or_unknown_code()
    {
        var store = new InMemoryAuthorizationCodeStore();

        (await store.GetAsync(""))
            .ShouldBeNull("GetAsync should return null for empty handle.");

        (await store.GetAsync("missing"))
            .ShouldBeNull("GetAsync should return null for unknown handle.");
    }

    [Fact]
    public async Task ConsumeAsync_sets_consumed_at_and_is_one_time_only()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryAuthorizationCodeStore(time);

        var code = new CoreIdentAuthorizationCode
        {
            Handle = "h-consume",
            ClientId = "client",
            SubjectId = "sub",
            RedirectUri = "https://client.example/cb",
            Scopes = ["openid"],
            CreatedAt = time.GetUtcNow().UtcDateTime,
            ExpiresAt = time.GetUtcNow().AddMinutes(5).UtcDateTime,
            CodeChallenge = "cc",
            CodeChallengeMethod = "S256"
        };

        await store.CreateAsync(code);

        (await store.ConsumeAsync("h-consume"))
            .ShouldBeTrue("First consume should succeed.");

        code.ConsumedAt.ShouldNotBeNull("ConsumeAsync should set ConsumedAt on the stored code.");

        (await store.ConsumeAsync("h-consume"))
            .ShouldBeFalse("Second consume should fail.");
    }

    [Fact]
    public async Task ConsumeAsync_returns_false_for_expired_code()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryAuthorizationCodeStore(time);

        var code = new CoreIdentAuthorizationCode
        {
            Handle = "h-exp",
            ClientId = "client",
            SubjectId = "sub",
            RedirectUri = "https://client.example/cb",
            Scopes = ["openid"],
            CreatedAt = time.GetUtcNow().UtcDateTime,
            ExpiresAt = time.GetUtcNow().AddSeconds(1).UtcDateTime,
            CodeChallenge = "cc",
            CodeChallengeMethod = "S256"
        };

        await store.CreateAsync(code);

        time.Advance(TimeSpan.FromSeconds(2));

        (await store.ConsumeAsync("h-exp"))
            .ShouldBeFalse("Expired code should not be consumable.");
    }

    [Fact]
    public async Task CleanupExpiredAsync_removes_expired_codes_only()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryAuthorizationCodeStore(time);

        var expired = new CoreIdentAuthorizationCode
        {
            Handle = "h-expired",
            ClientId = "client",
            SubjectId = "sub",
            RedirectUri = "https://client.example/cb",
            Scopes = ["openid"],
            CreatedAt = time.GetUtcNow().UtcDateTime,
            ExpiresAt = time.GetUtcNow().AddSeconds(1).UtcDateTime,
            CodeChallenge = "cc",
            CodeChallengeMethod = "S256"
        };

        var valid = new CoreIdentAuthorizationCode
        {
            Handle = "h-valid",
            ClientId = "client",
            SubjectId = "sub",
            RedirectUri = "https://client.example/cb",
            Scopes = ["openid"],
            CreatedAt = time.GetUtcNow().UtcDateTime,
            ExpiresAt = time.GetUtcNow().AddMinutes(5).UtcDateTime,
            CodeChallenge = "cc",
            CodeChallengeMethod = "S256"
        };

        await store.CreateAsync(expired);
        await store.CreateAsync(valid);

        time.Advance(TimeSpan.FromSeconds(2));

        await store.CleanupExpiredAsync();

        (await store.GetAsync("h-expired")).ShouldBeNull("Expired code should be removed by cleanup.");
        (await store.GetAsync("h-valid")).ShouldNotBeNull("Valid code should remain after cleanup.");
    }
}
