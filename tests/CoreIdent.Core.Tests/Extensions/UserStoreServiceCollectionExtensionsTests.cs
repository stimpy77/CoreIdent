using System.Security.Claims;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public sealed class UserStoreServiceCollectionExtensionsTests
{
    [Fact]
    public void AddUserStore_registers_custom_user_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddUserStore<TestUserStore>();

        // Assert
        services.ShouldContainScoped<IUserStore, TestUserStore>();
    }

    [Fact]
    public void AddUserStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddUserStore<TestUserStore>());
    }

    [Fact]
    public void AddInMemoryUserStore_registers_in_memory_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddInMemoryUserStore();

        // Assert
        services.ShouldContainSingleton<InMemoryUserStore>();
        services.ShouldContainSingleton<IUserStore, InMemoryUserStore>();
    }

    [Fact]
    public void AddInMemoryUserStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddInMemoryUserStore());
    }

    private class TestUserStore : IUserStore
    {
        public Task<CoreIdentUser?> FindByIdAsync(string id, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<CoreIdentUser?> FindByUsernameAsync(string username, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task CreateAsync(CoreIdentUser user, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task UpdateAsync(CoreIdentUser user, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task DeleteAsync(string id, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<System.Collections.Generic.IReadOnlyList<Claim>> GetClaimsAsync(string subjectId, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task SetClaimsAsync(string subjectId, System.Collections.Generic.IEnumerable<Claim> claims, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }
    }
}
