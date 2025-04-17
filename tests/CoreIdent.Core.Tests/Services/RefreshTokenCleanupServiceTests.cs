using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Tests.Infrastructure;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Shouldly;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class RefreshTokenCleanupServiceTests : SqliteInMemoryTestBase
{
    private readonly Mock<IOptions<CoreIdentOptions>> _mockOptions;
    private readonly Mock<ILogger<RefreshTokenCleanupService>> _mockLogger;
    private readonly CoreIdentOptions _options;
    private readonly IServiceProvider _serviceProvider;

    public RefreshTokenCleanupServiceTests()
    {
        // Set up the options
        _options = new CoreIdentOptions
        {
            RefreshTokenLifetime = TimeSpan.FromHours(1),
            ConsumedTokenRetentionPeriod = TimeSpan.FromDays(7)
        };

        _mockOptions = new Mock<IOptions<CoreIdentOptions>>();
        _mockOptions.Setup(o => o.Value).Returns(_options);

        _mockLogger = new Mock<ILogger<RefreshTokenCleanupService>>();

        // Create a simple service provider that returns our DbContext
        var serviceProviderMock = new Mock<IServiceProvider>();
        var serviceScopeMock = new Mock<IServiceScope>();
        var serviceScopeFactoryMock = new Mock<IServiceScopeFactory>();

        serviceScopeFactoryMock.Setup(x => x.CreateScope()).Returns(serviceScopeMock.Object);
        serviceScopeMock.Setup(x => x.ServiceProvider).Returns(serviceProviderMock.Object);
        serviceProviderMock.Setup(x => x.GetService(typeof(IServiceScopeFactory))).Returns(serviceScopeFactoryMock.Object);
        serviceProviderMock.Setup(x => x.GetService(typeof(CoreIdentDbContext))).Returns(DbContext);

        _serviceProvider = serviceProviderMock.Object;
    }

    [Fact]
    public async Task CleanupTokensAsync_ShouldRemoveExpiredTokens()
    {
        // Arrange
        var utcNow = DateTime.UtcNow;
        
        // Add expired token
        var expiredToken = new CoreIdentRefreshToken
        {
            Handle = "expired_token",
            ClientId = "client1",
            SubjectId = "user1",
            CreationTime = utcNow.AddHours(-2),
            ExpirationTime = utcNow.AddHours(-1), // Expired one hour ago
            FamilyId = "family1"
        };
        
        // Add valid token
        var validToken = new CoreIdentRefreshToken
        {
            Handle = "valid_token",
            ClientId = "client1",
            SubjectId = "user1",
            CreationTime = utcNow,
            ExpirationTime = utcNow.AddHours(1), // Valid for one more hour
            FamilyId = "family1"
        };
        
        // Add consumed token within retention period
        var recentConsumedToken = new CoreIdentRefreshToken
        {
            Handle = "recent_consumed_token",
            ClientId = "client1",
            SubjectId = "user1",
            CreationTime = utcNow.AddDays(-1),
            ExpirationTime = utcNow.AddDays(6),
            ConsumedTime = utcNow.AddHours(-1), // Consumed recently
            FamilyId = "family1"
        };
        
        // Add consumed token outside retention period
        var oldConsumedToken = new CoreIdentRefreshToken
        {
            Handle = "old_consumed_token",
            ClientId = "client1",
            SubjectId = "user1",
            CreationTime = utcNow.AddDays(-30),
            ExpirationTime = utcNow.AddDays(-23),
            ConsumedTime = utcNow.AddDays(-8), // Consumed outside retention period
            FamilyId = "family1"
        };
        
        DbContext.RefreshTokens.AddRange(expiredToken, validToken, recentConsumedToken, oldConsumedToken);
        await DbContext.SaveChangesAsync(CancellationToken.None);
        
        // Create service with direct testing method
        var service = new TestableRefreshTokenCleanupService(
            _serviceProvider,
            _mockOptions.Object,
            _mockLogger.Object
        );
        
        // Act
        await service.TestCleanupTokensAsync(CancellationToken.None);
        
        // Assert
        var remainingTokens = await DbContext.RefreshTokens.ToListAsync(CancellationToken.None);
        remainingTokens.Count.ShouldBe(2); // Only valid and recent consumed tokens should remain
        remainingTokens.ShouldContain(t => t.Handle == "valid_token");
        remainingTokens.ShouldContain(t => t.Handle == "recent_consumed_token");
        remainingTokens.ShouldNotContain(t => t.Handle == "expired_token");
        remainingTokens.ShouldNotContain(t => t.Handle == "old_consumed_token");
    }

    [Fact]
    public async Task CleanupTokensAsync_ShouldRespectRetentionPolicy_WhenDisabled()
    {
        // Arrange
        var utcNow = DateTime.UtcNow;
        
        // Set the retention period to null (keep indefinitely)
        _options.ConsumedTokenRetentionPeriod = null;
        
        // Add expired token
        var expiredToken = new CoreIdentRefreshToken
        {
            Handle = "expired_token",
            ClientId = "client1",
            SubjectId = "user1",
            CreationTime = utcNow.AddHours(-2),
            ExpirationTime = utcNow.AddHours(-1), // Expired one hour ago
            FamilyId = "family2"
        };
        
        // Add consumed token (should be kept with null retention)
        var consumedToken = new CoreIdentRefreshToken
        {
            Handle = "consumed_token",
            ClientId = "client1",
            SubjectId = "user1",
            CreationTime = utcNow.AddDays(-30),
            ExpirationTime = utcNow.AddDays(30),
            ConsumedTime = utcNow.AddDays(-20), // Consumed long ago
            FamilyId = "family2"
        };
        
        DbContext.RefreshTokens.AddRange(expiredToken, consumedToken);
        await DbContext.SaveChangesAsync(CancellationToken.None);
        
        // Create service with direct testing method
        var service = new TestableRefreshTokenCleanupService(
            _serviceProvider,
            _mockOptions.Object,
            _mockLogger.Object
        );
        
        // Act
        await service.TestCleanupTokensAsync(CancellationToken.None);
        
        // Assert
        var remainingTokens = await DbContext.RefreshTokens.ToListAsync(CancellationToken.None);
        remainingTokens.Count.ShouldBe(1); // Only consumed token should remain (expired one removed)
        remainingTokens.ShouldContain(t => t.Handle == "consumed_token");
        remainingTokens.ShouldNotContain(t => t.Handle == "expired_token");
    }

    // Helper class that exposes the protected method for testing
    private class TestableRefreshTokenCleanupService : RefreshTokenCleanupService
    {
        public TestableRefreshTokenCleanupService(
            IServiceProvider serviceProvider,
            IOptions<CoreIdentOptions> options,
            ILogger<RefreshTokenCleanupService> logger)
            : base(serviceProvider, options, logger)
        {
        }

        public Task TestCleanupTokensAsync(CancellationToken cancellationToken)
        {
            // Call the private method using reflection
            var methodInfo = typeof(RefreshTokenCleanupService).GetMethod(
                "CleanupTokensAsync", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            if (methodInfo == null)
            {
                throw new InvalidOperationException("Could not find private method CleanupTokensAsync using reflection.");
            }
            
            var result = (Task?)methodInfo.Invoke(this, new object[] { cancellationToken });
            return result ?? Task.CompletedTask;
        }
    }
}