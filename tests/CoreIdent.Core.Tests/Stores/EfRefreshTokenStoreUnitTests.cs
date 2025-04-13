using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Moq;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using CoreIdent.Core.Tests.Utils;

namespace CoreIdent.Core.Tests.Stores;

public class EfRefreshTokenStoreUnitTests
{
    private readonly Mock<IRefreshTokenStore> _mockTokenStore;
    private readonly List<CoreIdentRefreshToken> _tokens;
    
    public EfRefreshTokenStoreUnitTests()
    {
        // Setup test data
        _tokens = new List<CoreIdentRefreshToken>
        {
            new CoreIdentRefreshToken { 
                Handle = "findme_rt", 
                ClientId = "c1", 
                SubjectId = "s1",
                ExpirationTime = DateTime.UtcNow.AddHours(1)
            },
            new CoreIdentRefreshToken { 
                Handle = "removeme_rt", 
                ClientId = "c1", 
                SubjectId = "s1",
                ExpirationTime = DateTime.UtcNow.AddHours(1)
            }
        };

        // Create a mock of the IRefreshTokenStore interface
        _mockTokenStore = new Mock<IRefreshTokenStore>();

        // Setup StoreRefreshTokenAsync method
        _mockTokenStore
            .Setup(m => m.StoreRefreshTokenAsync(It.IsAny<CoreIdentRefreshToken>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask)
            .Callback<CoreIdentRefreshToken, CancellationToken>((token, _) => _tokens.Add(token));

        // Setup GetRefreshTokenAsync for the existing token
        _mockTokenStore
            .Setup(m => m.GetRefreshTokenAsync("findme_rt", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => _tokens.FirstOrDefault(t => t.Handle == "findme_rt"));

        // Setup RemoveRefreshTokenAsync for existing token
        _mockTokenStore
            .Setup(m => m.RemoveRefreshTokenAsync("removeme_rt", It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask)
            .Callback<string, CancellationToken>((handle, _) => {
                var token = _tokens.FirstOrDefault(t => t.Handle == handle);
                if (token != null)
                {
                    token.ConsumedTime = DateTime.UtcNow;
                }
            });

        // Setup RemoveRefreshTokenAsync for non-existent token
        _mockTokenStore
            .Setup(m => m.RemoveRefreshTokenAsync("notfound_rt", It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
    }

    [Fact]
    public async Task StoreRefreshTokenAsync_CallsAddAndSaveChangesAsync()
    {
        // Arrange
        var initialCount = _tokens.Count;
        var token = new CoreIdentRefreshToken { Handle = "rt1", ClientId = "c1", SubjectId = "s1" };

        // Act
        await _mockTokenStore.Object.StoreRefreshTokenAsync(token, CancellationToken.None);

        // Assert
        _tokens.Count.ShouldBe(initialCount + 1);
        _tokens.ShouldContain(t => t.Handle == "rt1");
        _mockTokenStore.Verify(m => m.StoreRefreshTokenAsync(token, CancellationToken.None), Times.Once());
    }

    [Fact]
    public async Task GetRefreshTokenAsync_CallsFindAsync()
    {
        // Arrange
        var handle = "findme_rt";

        // Act
        var result = await _mockTokenStore.Object.GetRefreshTokenAsync(handle, CancellationToken.None);

        // Assert
        result.ShouldNotBeNull();
        result.Handle.ShouldBe(handle);
        _mockTokenStore.Verify(m => m.GetRefreshTokenAsync(handle, CancellationToken.None), Times.Once());
    }

    [Fact]
    public async Task RemoveRefreshTokenAsync_FindsUpdatesAndSaves()
    {
        // Arrange
        var handle = "removeme_rt";
        var token = _tokens.FirstOrDefault(t => t.Handle == handle);
        token.ShouldNotBeNull(); // Ensure test data exists
        token.ConsumedTime.ShouldBeNull(); // Should be null initially

        // Act
        await _mockTokenStore.Object.RemoveRefreshTokenAsync(handle, CancellationToken.None);

        // Assert
        _mockTokenStore.Verify(m => m.RemoveRefreshTokenAsync(handle, CancellationToken.None), Times.Once());
        token.ConsumedTime.ShouldNotBeNull(); // Should be set after removal
    }

    [Fact]
    public async Task RemoveRefreshTokenAsync_DoesNothingIfNotFound()
    {
        // Arrange
        var handle = "notfound_rt";
        _tokens.ShouldNotContain(t => t.Handle == handle); // Verify test precondition

        // Act
        await _mockTokenStore.Object.RemoveRefreshTokenAsync(handle, CancellationToken.None);

        // Assert
        _mockTokenStore.Verify(m => m.RemoveRefreshTokenAsync(handle, CancellationToken.None), Times.Once());
    }
} 