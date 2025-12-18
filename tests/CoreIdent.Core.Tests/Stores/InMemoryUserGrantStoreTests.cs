using CoreIdent.Core.Models;
using CoreIdent.Core.Stores.InMemory;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Stores;

public class InMemoryUserGrantStoreTests
{
    [Fact]
    public async Task FindAsync_returns_null_when_subject_or_client_is_missing()
    {
        var store = new InMemoryUserGrantStore();

        (await store.FindAsync(subjectId: "", clientId: "c")).ShouldBeNull("Empty subjectId should return null.");
        (await store.FindAsync(subjectId: "s", clientId: "")).ShouldBeNull("Empty clientId should return null.");
        (await store.FindAsync(subjectId: " ", clientId: "c")).ShouldBeNull("Whitespace subjectId should return null.");
        (await store.FindAsync(subjectId: "s", clientId: " ")).ShouldBeNull("Whitespace clientId should return null.");
    }

    [Fact]
    public async Task SaveAsync_sets_created_at_when_default_and_round_trips_copy()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryUserGrantStore(time);

        var scopes = new List<string> { "openid", "profile" };

        var grant = new CoreIdentUserGrant
        {
            SubjectId = "sub-1",
            ClientId = "client-1",
            Scopes = scopes,
            CreatedAt = default
        };

        await store.SaveAsync(grant);

        grant.CreatedAt.ShouldNotBe(default(DateTime), "SaveAsync should populate CreatedAt when it is default.");

        var roundTrip = await store.FindAsync("sub-1", "client-1");
        roundTrip.ShouldNotBeNull("Stored grant should be retrievable.");

        roundTrip!.Scopes.ShouldBe(scopes, "Stored grant scopes should match input scopes.");

        scopes.Add("email");

        var secondRead = await store.FindAsync("sub-1", "client-1");
        secondRead.ShouldNotBeNull();
        secondRead!.Scopes.ShouldBe(new[] { "openid", "profile" }, "Stored grant should not be affected by mutations to the input list.");
    }

    [Fact]
    public async Task FindAsync_removes_and_returns_null_for_expired_grants()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryUserGrantStore(time);

        await store.SaveAsync(new CoreIdentUserGrant
        {
            SubjectId = "sub-exp",
            ClientId = "client-exp",
            Scopes = ["openid"],
            CreatedAt = time.GetUtcNow().UtcDateTime,
            ExpiresAt = time.GetUtcNow().AddSeconds(-1).UtcDateTime
        });

        (await store.FindAsync("sub-exp", "client-exp")).ShouldBeNull("Expired grant should not be returned.");

        var hasConsent = await store.HasUserGrantedConsentAsync("sub-exp", "client-exp", new[] { "openid" });
        hasConsent.ShouldBeFalse("Expired grant should be removed and not satisfy consent checks.");
    }

    [Fact]
    public async Task HasUserGrantedConsentAsync_requires_all_requested_scopes()
    {
        var store = new InMemoryUserGrantStore();

        await store.SaveAsync(new CoreIdentUserGrant
        {
            SubjectId = "sub-2",
            ClientId = "client-2",
            Scopes = ["openid", "profile"],
            CreatedAt = DateTime.UtcNow
        });

        (await store.HasUserGrantedConsentAsync("sub-2", "client-2", new[] { "openid" }))
            .ShouldBeTrue("Consent should be granted when all requested scopes are in the grant.");

        (await store.HasUserGrantedConsentAsync("sub-2", "client-2", new[] { "openid", "email" }))
            .ShouldBeFalse("Consent should be denied when any requested scope is missing.");
    }

    [Fact]
    public async Task RevokeAsync_removes_grant_and_is_noop_for_missing_ids()
    {
        var store = new InMemoryUserGrantStore();

        await store.SaveAsync(new CoreIdentUserGrant
        {
            SubjectId = "sub-3",
            ClientId = "client-3",
            Scopes = ["openid"],
            CreatedAt = DateTime.UtcNow
        });

        await store.RevokeAsync("sub-3", "client-3");

        (await store.FindAsync("sub-3", "client-3")).ShouldBeNull("Revoked grant should not be retrievable.");

        await store.RevokeAsync(subjectId: "", clientId: "client-3");
        await store.RevokeAsync(subjectId: "sub-3", clientId: "");
    }

    [Fact]
    public async Task SaveAsync_throws_for_invalid_arguments()
    {
        var store = new InMemoryUserGrantStore();

        await Should.ThrowAsync<ArgumentNullException>(() => store.SaveAsync(null!), "SaveAsync should throw for null grant.");

        var missingSubject = new CoreIdentUserGrant { SubjectId = "", ClientId = "c", Scopes = [], CreatedAt = DateTime.UtcNow };
        await Should.ThrowAsync<ArgumentException>(() => store.SaveAsync(missingSubject), "SaveAsync should throw when SubjectId is missing.");

        var missingClient = new CoreIdentUserGrant { SubjectId = "s", ClientId = "", Scopes = [], CreatedAt = DateTime.UtcNow };
        await Should.ThrowAsync<ArgumentException>(() => store.SaveAsync(missingClient), "SaveAsync should throw when ClientId is missing.");
    }
}
