using CoreIdent.Core.Models;
using CoreIdent.Core.Stores.InMemory;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class InMemoryScopeStoreTests
{
    private static CoreIdentScope CreateTestScope(string name = "test-scope") => new()
    {
        Name = name,
        DisplayName = "Test Scope",
        Description = "A test scope",
        Required = false,
        Emphasize = false,
        ShowInDiscoveryDocument = true,
        UserClaims = ["claim1", "claim2"]
    };

    [Fact]
    public async Task FindByNameAsync_ReturnsNull_WhenScopeDoesNotExist()
    {
        var store = new InMemoryScopeStore();

        var result = await store.FindByNameAsync("nonexistent");

        result.ShouldBeNull("should return null for non-existent scope");
    }

    [Fact]
    public async Task FindByNameAsync_ReturnsScope_WhenScopeExists()
    {
        var store = new InMemoryScopeStore();
        var scope = CreateTestScope();
        store.SeedScopes([scope]);

        var result = await store.FindByNameAsync(scope.Name);

        result.ShouldNotBeNull("should find seeded scope");
        result.Name.ShouldBe(scope.Name, "scope name should match");
        result.DisplayName.ShouldBe(scope.DisplayName, "display name should match");
    }

    [Fact]
    public async Task FindByNameAsync_IsCaseInsensitive()
    {
        var store = new InMemoryScopeStore();
        var scope = CreateTestScope("TestScope");
        store.SeedScopes([scope]);

        var result = await store.FindByNameAsync("testscope");

        result.ShouldNotBeNull("should find scope with case-insensitive lookup");
        result.Name.ShouldBe("TestScope", "original scope name should be preserved");
    }

    [Fact]
    public async Task FindByScopesAsync_ReturnsMatchingScopes()
    {
        var store = new InMemoryScopeStore();
        var scope1 = CreateTestScope("scope1");
        var scope2 = CreateTestScope("scope2");
        var scope3 = CreateTestScope("scope3");
        store.SeedScopes([scope1, scope2, scope3]);

        var result = await store.FindByScopesAsync(["scope1", "scope3", "nonexistent"]);

        var resultList = result.ToList();
        resultList.Count.ShouldBe(2, "should return only existing scopes");
        resultList.ShouldContain(s => s.Name == "scope1", "should contain scope1");
        resultList.ShouldContain(s => s.Name == "scope3", "should contain scope3");
    }

    [Fact]
    public async Task FindByScopesAsync_ReturnsEmpty_WhenNoScopesMatch()
    {
        var store = new InMemoryScopeStore();

        var result = await store.FindByScopesAsync(["nonexistent1", "nonexistent2"]);

        result.ShouldBeEmpty("should return empty when no scopes match");
    }

    [Fact]
    public async Task GetAllAsync_ReturnsAllScopes()
    {
        var store = new InMemoryScopeStore();
        var scope1 = CreateTestScope("scope1");
        var scope2 = CreateTestScope("scope2");
        store.SeedScopes([scope1, scope2]);

        var result = await store.GetAllAsync();

        var resultList = result.ToList();
        resultList.Count.ShouldBe(2, "should return all seeded scopes");
    }

    [Fact]
    public async Task GetAllAsync_ReturnsEmpty_WhenNoScopes()
    {
        var store = new InMemoryScopeStore();

        var result = await store.GetAllAsync();

        result.ShouldBeEmpty("should return empty when no scopes seeded");
    }

    [Fact]
    public async Task SeedStandardScopes_AddsAllStandardOidcScopes()
    {
        var store = new InMemoryScopeStore();

        store.SeedStandardScopes();

        var openid = await store.FindByNameAsync(StandardScopes.OpenId);
        openid.ShouldNotBeNull("should contain openid scope");
        openid.Required.ShouldBeTrue("openid scope should be required");

        var profile = await store.FindByNameAsync(StandardScopes.Profile);
        profile.ShouldNotBeNull("should contain profile scope");
        profile.UserClaims.ShouldContain("name", "profile scope should include name claim");

        var email = await store.FindByNameAsync(StandardScopes.Email);
        email.ShouldNotBeNull("should contain email scope");
        email.UserClaims.ShouldContain("email", "email scope should include email claim");

        var address = await store.FindByNameAsync(StandardScopes.Address);
        address.ShouldNotBeNull("should contain address scope");

        var phone = await store.FindByNameAsync(StandardScopes.Phone);
        phone.ShouldNotBeNull("should contain phone scope");

        var offlineAccess = await store.FindByNameAsync(StandardScopes.OfflineAccess);
        offlineAccess.ShouldNotBeNull("should contain offline_access scope");
    }

    [Fact]
    public async Task Constructor_WithScopes_SeedsScopes()
    {
        var scope = CreateTestScope();

        var store = new InMemoryScopeStore([scope]);

        var result = await store.FindByNameAsync(scope.Name);
        result.ShouldNotBeNull("constructor should seed provided scopes");
    }
}
