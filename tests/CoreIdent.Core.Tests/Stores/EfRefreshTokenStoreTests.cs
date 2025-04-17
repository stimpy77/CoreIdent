using CoreIdent.Core.Models;
using CoreIdent.Core.Tests.Infrastructure;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Shouldly;
using System.Threading.Tasks;
using Xunit;
using System;
using Microsoft.EntityFrameworkCore;
using System.Threading;
using Microsoft.Extensions.Logging;
using Moq;

namespace CoreIdent.Core.Tests.Stores;

public class EfRefreshTokenStoreTests : SqliteInMemoryTestBase
{
    private readonly EfRefreshTokenStore _refreshTokenStore;
    private readonly Mock<ILogger<EfRefreshTokenStore>> _mockLogger;

    public EfRefreshTokenStoreTests()
    {
        _mockLogger = new Mock<ILogger<EfRefreshTokenStore>>();
        _refreshTokenStore = new EfRefreshTokenStore(DbContext, _mockLogger.Object);
    }

    [Fact]
    public async Task StoreRefreshTokenAsync_ShouldAddToken()
    {
        // Arrange
        var token = new CoreIdentRefreshToken
        {
            Handle = "test_handle_1",
            ClientId = "client1",
            SubjectId = "user1",
            ExpirationTime = DateTime.UtcNow.AddHours(1),
            FamilyId = "family1"
        };

        // Act
        await _refreshTokenStore.StoreRefreshTokenAsync(token, CancellationToken.None);
        var foundToken = await DbContext.RefreshTokens.FindAsync(new object[] { token.Handle }, CancellationToken.None);

        // Assert
        foundToken.ShouldNotBeNull();
        foundToken.Handle.ShouldBe(token.Handle);
        foundToken.ClientId.ShouldBe(token.ClientId);
        foundToken.SubjectId.ShouldBe(token.SubjectId);
        foundToken.ExpirationTime.ShouldBe(token.ExpirationTime);
        foundToken.ConsumedTime.ShouldBeNull();
    }

    [Fact]
    public async Task GetRefreshTokenAsync_ShouldReturnToken_WhenExists()
    {
        // Arrange
        var handle = "test_handle_get";
        var token = new CoreIdentRefreshToken
        {
            Handle = handle,
            ClientId = "client_get",
            SubjectId = "user_get",
            ExpirationTime = DateTime.UtcNow.AddHours(1),
            FamilyId = "family_get"
        };
        await _refreshTokenStore.StoreRefreshTokenAsync(token, CancellationToken.None);

        // Act
        var foundToken = await _refreshTokenStore.GetRefreshTokenAsync(handle, CancellationToken.None);

        // Assert
        foundToken.ShouldNotBeNull();
        foundToken.Handle.ShouldBe(handle);
    }

    [Fact]
    public async Task GetRefreshTokenAsync_ShouldReturnNull_WhenNotExists()
    {
        // Arrange
        var nonExistentHandle = "does_not_exist";

        // Act
        var foundToken = await _refreshTokenStore.GetRefreshTokenAsync(nonExistentHandle, CancellationToken.None);

        // Assert
        foundToken.ShouldBeNull();
    }

    [Fact]
    public async Task RemoveRefreshTokenAsync_ShouldMarkTokenAsConsumed_WhenExists()
    {
        // Arrange
        var handle = "test_handle_remove";
        var token = new CoreIdentRefreshToken
        {
            Handle = handle,
            ClientId = "client_remove",
            SubjectId = "user_remove",
            ExpirationTime = DateTime.UtcNow.AddHours(1),
            FamilyId = "family_remove"
        };
        await _refreshTokenStore.StoreRefreshTokenAsync(token, CancellationToken.None);

        // Act
        await _refreshTokenStore.RemoveRefreshTokenAsync(handle, CancellationToken.None);
        var foundTokenAfterRemoveAttempt = await DbContext.RefreshTokens.FindAsync(new object[] { handle }, CancellationToken.None);

        // Assert
        foundTokenAfterRemoveAttempt.ShouldNotBeNull(); // Should still exist because we mark as consumed
        foundTokenAfterRemoveAttempt.ConsumedTime.ShouldNotBeNull();
        foundTokenAfterRemoveAttempt.ConsumedTime.Value.ShouldBeInRange(DateTime.UtcNow.AddSeconds(-5), DateTime.UtcNow.AddSeconds(5));
    }

    [Fact]
    public async Task RemoveRefreshTokenAsync_ShouldDoNothing_WhenNotExists()
    {
        // Arrange
        var nonExistentHandle = "does_not_exist_remove";
        var initialCount = await DbContext.RefreshTokens.CountAsync(CancellationToken.None);

        // Act & Assert (Should not throw)
        await Should.NotThrowAsync(async () => await _refreshTokenStore.RemoveRefreshTokenAsync(nonExistentHandle, CancellationToken.None));
        var finalCount = await DbContext.RefreshTokens.CountAsync(CancellationToken.None);
        finalCount.ShouldBe(initialCount);
    }
} 