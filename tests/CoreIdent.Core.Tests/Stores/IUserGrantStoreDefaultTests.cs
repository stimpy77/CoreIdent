using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Stores;

/// <summary>
/// Tests the default interface method <see cref="IUserGrantStore.MergeScopesAsync"/>
/// using a minimal stub that does NOT override the default.
/// </summary>
public class IUserGrantStoreDefaultTests
{
    /// <summary>
    /// Minimal stub that only implements required members, leaving the default MergeScopesAsync.
    /// </summary>
    private sealed class StubUserGrantStore : IUserGrantStore
    {
        private readonly Dictionary<string, CoreIdentUserGrant> _grants = new(StringComparer.Ordinal);

        public Task<CoreIdentUserGrant?> FindAsync(string subjectId, string clientId, CancellationToken ct = default)
        {
            _grants.TryGetValue($"{subjectId}::{clientId}", out var grant);
            return Task.FromResult(grant);
        }

        public Task SaveAsync(CoreIdentUserGrant grant, CancellationToken ct = default)
        {
            _grants[$"{grant.SubjectId}::{grant.ClientId}"] = grant;
            return Task.CompletedTask;
        }

        public Task RevokeAsync(string subjectId, string clientId, CancellationToken ct = default)
        {
            _grants.Remove($"{subjectId}::{clientId}");
            return Task.CompletedTask;
        }

        public Task<bool> HasUserGrantedConsentAsync(string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default)
        {
            if (!_grants.TryGetValue($"{subjectId}::{clientId}", out var grant))
                return Task.FromResult(false);
            var granted = grant.Scopes.ToHashSet(StringComparer.Ordinal);
            return Task.FromResult(scopes.All(s => granted.Contains(s)));
        }
    }

    [Fact]
    public async Task Default_MergeScopesAsync_creates_grant_when_none_exists()
    {
        IUserGrantStore store = new StubUserGrantStore();

        await store.MergeScopesAsync("sub-d1", "client-d1", ["openid", "profile"]);

        var grant = await store.FindAsync("sub-d1", "client-d1");
        grant.ShouldNotBeNull("Default MergeScopesAsync should create a new grant.");
        grant!.Scopes.ShouldBe(new[] { "openid", "profile" }, "New grant should contain the provided scopes.");
    }

    [Fact]
    public async Task Default_MergeScopesAsync_merges_into_existing_grant()
    {
        IUserGrantStore store = new StubUserGrantStore();

        await store.SaveAsync(new CoreIdentUserGrant
        {
            SubjectId = "sub-d2",
            ClientId = "client-d2",
            Scopes = ["openid"],
            CreatedAt = DateTime.UtcNow
        });

        await store.MergeScopesAsync("sub-d2", "client-d2", ["profile", "email"]);

        var grant = await store.FindAsync("sub-d2", "client-d2");
        grant.ShouldNotBeNull("Grant should still exist after merge.");
        grant!.Scopes.Count.ShouldBe(3, "Merged grant should have union of scopes.");
        grant.Scopes.ShouldContain("openid", "Existing scope should be preserved.");
        grant.Scopes.ShouldContain("profile", "New scope should be added.");
        grant.Scopes.ShouldContain("email", "New scope should be added.");
    }

    [Fact]
    public async Task Default_MergeScopesAsync_throws_for_invalid_arguments()
    {
        IUserGrantStore store = new StubUserGrantStore();

        await Should.ThrowAsync<ArgumentException>(
            () => store.MergeScopesAsync("", "client", ["openid"]),
            "Default MergeScopesAsync should throw for empty subjectId.");

        await Should.ThrowAsync<ArgumentException>(
            () => store.MergeScopesAsync("sub", "", ["openid"]),
            "Default MergeScopesAsync should throw for empty clientId.");

        await Should.ThrowAsync<ArgumentNullException>(
            () => store.MergeScopesAsync("sub", "client", null!),
            "Default MergeScopesAsync should throw for null scopes.");
    }
}
