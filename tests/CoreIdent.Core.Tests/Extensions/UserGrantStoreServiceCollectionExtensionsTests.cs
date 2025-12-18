using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public sealed class UserGrantStoreServiceCollectionExtensionsTests
{
    [Fact]
    public void AddUserGrantStore_registers_custom_user_grant_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddUserGrantStore<TestUserGrantStore>();

        // Assert
        services.ShouldContainScoped<IUserGrantStore, TestUserGrantStore>();
    }

    [Fact]
    public void AddUserGrantStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddUserGrantStore<TestUserGrantStore>());
    }

    [Fact]
    public void AddInMemoryUserGrantStore_registers_in_memory_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddInMemoryUserGrantStore();

        // Assert
        services.ShouldContainSingleton<InMemoryUserGrantStore>();
        services.ShouldContainSingleton<IUserGrantStore, InMemoryUserGrantStore>();
    }

    [Fact]
    public void AddInMemoryUserGrantStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddInMemoryUserGrantStore());
    }

    private class TestUserGrantStore : IUserGrantStore
    {
        public Task<CoreIdentUserGrant?> FindAsync(string subjectId, string clientId, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task SaveAsync(CoreIdentUserGrant grant, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task RevokeAsync(string subjectId, string clientId, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<bool> HasUserGrantedConsentAsync(string subjectId, string clientId, System.Collections.Generic.IEnumerable<string> scopes, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }
    }
}
