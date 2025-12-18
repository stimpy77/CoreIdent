using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.DependencyInjection;
using CoreIdent.Core.Tests.TestUtilities;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public sealed class RefreshTokenStoreServiceCollectionExtensionsTests
{
    [Fact]
    public void AddRefreshTokenStore_registers_custom_refresh_token_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddRefreshTokenStore<TestRefreshTokenStore>();

        // Assert
        services.ShouldContainScoped<IRefreshTokenStore, TestRefreshTokenStore>();
    }

    [Fact]
    public void AddRefreshTokenStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddRefreshTokenStore<TestRefreshTokenStore>());
    }

    [Fact]
    public void AddInMemoryRefreshTokenStore_registers_in_memory_store()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddInMemoryRefreshTokenStore();

        // Assert
        services.ShouldContainSingleton<InMemoryRefreshTokenStore>();
        services.ShouldContainSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
    }

    [Fact]
    public void AddInMemoryRefreshTokenStore_with_null_services_throws()
    {
        // Arrange
        IServiceCollection? services = null;

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => services!.AddInMemoryRefreshTokenStore());
    }

    private class TestRefreshTokenStore : IRefreshTokenStore
    {
        public Task<string> StoreAsync(CoreIdent.Core.Models.CoreIdentRefreshToken refreshToken, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<CoreIdent.Core.Models.CoreIdentRefreshToken?> GetAsync(string handle, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task<bool> RevokeAsync(string handle, System.Threading.CancellationToken cancellationToken = default)
        {
            throw new System.NotImplementedException();
        }

        public Task RevokeFamilyAsync(string familyId, System.Threading.CancellationToken cancellationToken = default)
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
