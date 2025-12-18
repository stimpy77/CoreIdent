using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public sealed class ScopeStoreServiceCollectionExtensionsTests
{
    [Fact]
    public void AddScopeStore_registers_custom_scope_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddScopeStore<TestScopeStore>();

        // Assert
        services.ShouldContainScoped<IScopeStore, TestScopeStore>();
    }

    [Fact]
    public void AddScopeStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddScopeStore<TestScopeStore>());
    }

    [Fact]
    public void AddInMemoryScopeStore_registers_in_memory_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddInMemoryScopeStore();

        // Assert
        services.ShouldContainSingleton<InMemoryScopeStore>();
        services.ShouldContainSingleton<IScopeStore, InMemoryScopeStore>();
    }

    [Fact]
    public void AddInMemoryScopeStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddInMemoryScopeStore());
    }

    [Fact]
    public async Task AddInMemoryScopes_registers_and_seeds_store()
    {
        // Arrange
        var services = new ServiceCollection();
        var scopes = new[]
        {
            new CoreIdentScope
            {
                Name = "read",
                DisplayName = "Read Access",
                Description = "Read access to resources"
            },
            new CoreIdentScope
            {
                Name = "write",
                DisplayName = "Write Access", 
                Description = "Write access to resources"
            }
        };

        // Act
        services.AddInMemoryScopes(scopes);

        // Assert
        services.ShouldContainSingleton<InMemoryScopeStore>();
        services.ShouldContainSingleton<IScopeStore, InMemoryScopeStore>();

        // Verify seeding
        var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<IScopeStore>();
        
        var readScope = await store.FindByNameAsync("read");
        readScope.ShouldNotBeNull();
        readScope.DisplayName.ShouldBe("Read Access");

        var writeScope = await store.FindByNameAsync("write");
        writeScope.ShouldNotBeNull();
        writeScope.DisplayName.ShouldBe("Write Access");
    }

    [Fact]
    public void AddInMemoryScopes_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;
        var scopes = Array.Empty<CoreIdentScope>();

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddInMemoryScopes(scopes));
    }

    [Fact]
    public void AddInMemoryScopes_with_null_scopes_throws()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services.AddInMemoryScopes(null!));
    }

    [Fact]
    public async Task AddInMemoryStandardScopes_registers_and_seeds_standard_scopes()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddInMemoryStandardScopes();

        // Assert
        services.ShouldContainSingleton<InMemoryScopeStore>();
        services.ShouldContainSingleton<IScopeStore, InMemoryScopeStore>();

        // Verify standard scopes are seeded
        var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<IScopeStore>();
        
        var openidScope = await store.FindByNameAsync("openid");
        openidScope.ShouldNotBeNull();
        openidScope.DisplayName.ShouldBe("OpenID");

        var profileScope = await store.FindByNameAsync("profile");
        profileScope.ShouldNotBeNull();
        profileScope.DisplayName.ShouldBe("Profile");

        var emailScope = await store.FindByNameAsync("email");
        emailScope.ShouldNotBeNull();
        emailScope.DisplayName.ShouldBe("Email");
    }

    [Fact]
    public void AddInMemoryStandardScopes_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddInMemoryStandardScopes());
    }

    [Fact]
    public void AddInMemoryScopes_with_empty_collection_registers_store()
    {
        // Arrange
        var services = new ServiceCollection();
        var emptyScopes = Array.Empty<CoreIdentScope>();

        // Act
        services.AddInMemoryScopes(emptyScopes);

        // Assert
        services.ShouldContainSingleton<InMemoryScopeStore>();
        services.ShouldContainSingleton<IScopeStore, InMemoryScopeStore>();
    }

    private class TestScopeStore : IScopeStore
    {
        public Task<CoreIdentScope?> FindByNameAsync(string name, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<System.Collections.Generic.IEnumerable<CoreIdentScope>> FindByScopesAsync(System.Collections.Generic.IEnumerable<string> scopeNames, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<System.Collections.Generic.IEnumerable<CoreIdentScope>> GetAllAsync(System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }
    }
}
