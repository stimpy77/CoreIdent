using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class EfScopeStoreTests : IDisposable
{
    private readonly CoreIdentDbContext _context;
    private readonly EfScopeStore _store;

    public EfScopeStoreTests()
    {
        var options = new DbContextOptionsBuilder<CoreIdentDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;

        _context = new CoreIdentDbContext(options);
        _context.Database.OpenConnection();
        _context.Database.EnsureCreated();

        _store = new EfScopeStore(_context);
    }

    public void Dispose()
    {
        _context.Database.CloseConnection();
        _context.Dispose();
    }

    private async Task SeedScopesAsync(params ScopeEntity[] entities)
    {
        _context.Scopes.AddRange(entities);
        await _context.SaveChangesAsync();
    }

    [Fact]
    public async Task FindByNameAsync_ReturnsNull_WhenScopeDoesNotExist()
    {
        var result = await _store.FindByNameAsync("nonexistent");

        result.ShouldBeNull("should return null for non-existent scope");
    }

    [Fact]
    public async Task FindByNameAsync_ReturnsScope_WhenScopeExists()
    {
        await SeedScopesAsync(new ScopeEntity
        {
            Name = "profile",
            DisplayName = "Profile",
            Description = "Profile scope",
            Required = false,
            Emphasize = true,
            ShowInDiscoveryDocument = true,
            UserClaimsJson = JsonSerializer.Serialize(new[] { "name", "family_name" })
        });

        var result = await _store.FindByNameAsync("profile");

        result.ShouldNotBeNull("should find seeded scope");
        result.Name.ShouldBe("profile", "scope name should match");
        result.DisplayName.ShouldBe("Profile", "display name should match");
        result.UserClaims.ShouldContain("name", "user claims should be deserialized");
    }

    [Fact]
    public async Task FindByScopesAsync_ReturnsOnlyRequestedScopesThatExist()
    {
        await SeedScopesAsync(
            new ScopeEntity { Name = "openid", UserClaimsJson = "[]" },
            new ScopeEntity { Name = "email", UserClaimsJson = JsonSerializer.Serialize(new[] { "email" }) },
            new ScopeEntity { Name = "profile", UserClaimsJson = JsonSerializer.Serialize(new[] { "name" }) });

        var result = await _store.FindByScopesAsync(["openid", "profile", "nonexistent"]);

        var list = result.ToList();
        list.Count.ShouldBe(2, "should return only existing scopes");
        list.ShouldContain(s => s.Name == "openid", "should contain openid");
        list.ShouldContain(s => s.Name == "profile", "should contain profile");
    }

    [Fact]
    public async Task GetAllAsync_ReturnsAllScopes()
    {
        await SeedScopesAsync(
            new ScopeEntity { Name = "openid", UserClaimsJson = "[]" },
            new ScopeEntity { Name = "profile", UserClaimsJson = JsonSerializer.Serialize(new[] { "name" }) });

        var result = await _store.GetAllAsync();

        var list = result.ToList();
        list.Count.ShouldBe(2, "should return all scopes");
    }
}
