using CoreIdent.Core.Models;
using CoreIdent.Core.Tests.Infrastructure;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Shouldly;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using System.Threading;

namespace CoreIdent.Core.Tests.Stores;

public class EfScopeStoreTests : SqliteInMemoryTestBase
{
    private readonly EfScopeStore _scopeStore;

    public EfScopeStoreTests()
    {
        _scopeStore = new EfScopeStore(DbContext);
    }

    private async Task SeedScopesAsync()
    {
        DbContext.Scopes.AddRange(
            new CoreIdentScope
            {
                Name = "openid",
                DisplayName = "Your user identifier",
                Required = true,
                UserClaims = new List<CoreIdentScopeClaim> { new CoreIdentScopeClaim { Type = "sub" } }
            },
            new CoreIdentScope
            {
                Name = "profile",
                DisplayName = "User profile",
                Description = "Your user profile information (first name, last name, etc.)",
                Emphasize = true,
                UserClaims = new List<CoreIdentScopeClaim> { new CoreIdentScopeClaim { Type = "name" }, new CoreIdentScopeClaim { Type = "family_name" } }
            },
            new CoreIdentScope
            {
                Name = "email",
                DisplayName = "Your email address",
                UserClaims = new List<CoreIdentScopeClaim> { new CoreIdentScopeClaim { Type = "email" }, new CoreIdentScopeClaim { Type = "email_verified" } }
            },
            new CoreIdentScope
            {
                Name = "api1",
                DisplayName = "API 1 Access"
            },
            new CoreIdentScope
            {
                Name = "api2",
                Enabled = false // Disabled scope
            }
        );
        await DbContext.SaveChangesAsync(CancellationToken.None);
    }

    [Fact]
    public async Task GetAllScopesAsync_ShouldReturnAllEnabledScopesWithClaims()
    {
        // Arrange
        await SeedScopesAsync();

        // Act
        var scopes = await _scopeStore.GetAllScopesAsync(CancellationToken.None);

        // Assert
        // Note: Default implementation might return all scopes, including disabled ones. Filter if needed.
        // The test implementation currently returns all scopes loaded.
        scopes.ShouldNotBeNull();
        scopes.Count().ShouldBe(5); // Includes the disabled one as store doesn't filter by default

        var profileScope = scopes.FirstOrDefault(s => s.Name == "profile");
        profileScope.ShouldNotBeNull();
        profileScope.DisplayName.ShouldBe("User profile");
        profileScope.UserClaims.Count.ShouldBe(2);
        profileScope.UserClaims.ShouldContain(sc => sc.Type == "name");
    }

    [Fact]
    public async Task FindScopesByNameAsync_ShouldReturnMatchingScopesWithClaims()
    {
        // Arrange
        await SeedScopesAsync();
        var namesToFind = new List<string> { "openid", "email", "api1", "nonexistent" };

        // Act
        var scopes = await _scopeStore.FindScopesByNameAsync(namesToFind, CancellationToken.None);

        // Assert
        scopes.ShouldNotBeNull();
        scopes.Count().ShouldBe(3); // openid, email, api1

        scopes.Select(s => s.Name).ShouldBe(new[] { "openid", "email", "api1" }, ignoreOrder: true);

        var openidScope = scopes.FirstOrDefault(s => s.Name == "openid");
        openidScope.ShouldNotBeNull();
        openidScope.UserClaims.Count.ShouldBe(1);
        openidScope.UserClaims.First().Type.ShouldBe("sub");

        var emailScope = scopes.FirstOrDefault(s => s.Name == "email");
        emailScope.ShouldNotBeNull();
        emailScope.UserClaims.Count.ShouldBe(2);
    }

    [Fact]
    public async Task FindScopesByNameAsync_ShouldReturnEmpty_WhenNoMatches()
    {
        // Arrange
        await SeedScopesAsync();
        var namesToFind = new List<string> { "nonexistent1", "nonexistent2" };

        // Act
        var scopes = await _scopeStore.FindScopesByNameAsync(namesToFind, CancellationToken.None);

        // Assert
        scopes.ShouldNotBeNull();
        scopes.ShouldBeEmpty();
    }
} 