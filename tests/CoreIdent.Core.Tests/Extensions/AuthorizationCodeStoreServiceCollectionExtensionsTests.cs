using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public sealed class AuthorizationCodeStoreServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAuthorizationCodeStore_registers_custom_authorization_code_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddAuthorizationCodeStore<TestAuthorizationCodeStore>();

        // Assert
        services.ShouldContainScoped<IAuthorizationCodeStore, TestAuthorizationCodeStore>();
    }

    [Fact]
    public void AddAuthorizationCodeStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddAuthorizationCodeStore<TestAuthorizationCodeStore>());
    }

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_registers_in_memory_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddInMemoryAuthorizationCodeStore();

        // Assert
        services.ShouldContainSingleton<InMemoryAuthorizationCodeStore>();
        services.ShouldContainSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
    }

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddInMemoryAuthorizationCodeStore());
    }

    private class TestAuthorizationCodeStore : IAuthorizationCodeStore
    {
        public Task CreateAsync(CoreIdent.Core.Models.CoreIdentAuthorizationCode code, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<CoreIdent.Core.Models.CoreIdentAuthorizationCode?> GetAsync(string handle, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<bool> ConsumeAsync(string handle, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task CleanupExpiredAsync(System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }
    }
}
