using CoreIdent.Core.Models;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.EntityFrameworkCore;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Core.Tests.Stores;

public class EfAuthorizationCodeStoreTests
{
    private readonly Mock<CoreIdentDbContext> _mockContext;
    private readonly Mock<ILogger<EfAuthorizationCodeStore>> _mockLogger;
    private readonly EfAuthorizationCodeStore _store;
    private readonly List<AuthorizationCode> _authCodes;

    public EfAuthorizationCodeStoreTests()
    {
        // Moq DbContext
        // Using Moq.EntityFrameworkCore helpers for DbSet mocking
        var options = new DbContextOptionsBuilder<CoreIdentDbContext>().Options; // Dummy options
        _mockContext = new Mock<CoreIdentDbContext>(options);

        _authCodes = new List<AuthorizationCode>();
        _mockContext.Setup(x => x.AuthorizationCodes).ReturnsDbSet(_authCodes);

        _mockLogger = new Mock<ILogger<EfAuthorizationCodeStore>>();

        _store = new EfAuthorizationCodeStore(_mockContext.Object, _mockLogger.Object);
    }

    // --- RemoveAuthorizationCodeAsync Tests ---

    [Fact]
    public async Task RemoveAuthorizationCodeAsync_WhenCodeExists_RemovesAndSaves()
    {
        // Arrange
        var code = new AuthorizationCode { CodeHandle = "existing_code", ClientId = "c1", SubjectId = "s1", ExpirationTime = DateTime.UtcNow.AddMinutes(5) };
        _authCodes.Add(code);
        var cancellationToken = CancellationToken.None;

        // Set up Find to return our code to simulate EF's FirstOrDefaultAsync behavior
        _mockContext.Setup(m => m.AuthorizationCodes.FindAsync(
            It.Is<object[]>(o => o.Length == 1 && o[0].ToString() == code.CodeHandle),
            It.IsAny<CancellationToken>()))
            .ReturnsAsync(code);

        // Set up Remove to actually modify the list
        _mockContext.Setup(m => m.AuthorizationCodes.Remove(code))
            .Callback(() => _authCodes.Remove(code));

        // Act
        await _store.RemoveAuthorizationCodeAsync(code.CodeHandle, cancellationToken);

        // Assert
        _mockContext.Verify(m => m.SaveChangesAsync(cancellationToken), Times.Once());
        _authCodes.ShouldNotContain(code);
        // Verify logging (optional, but good practice)
#pragma warning disable CS8602 // Dereference of a possibly null reference
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Authorization code removed successfully.")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
#pragma warning restore CS8602
    }

    [Fact]
    public async Task RemoveAuthorizationCodeAsync_WhenCodeDoesNotExist_DoesNotSaveChanges()
    {
        // Arrange
        var nonExistentCodeHandle = "non_existent_code";
        var cancellationToken = CancellationToken.None;

        // Act
        await _store.RemoveAuthorizationCodeAsync(nonExistentCodeHandle, cancellationToken);

        // Assert
        _mockContext.Verify(m => m.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never());
        // Verify logging
#pragma warning disable CS8602
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Authorization code not found during removal attempt.")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
#pragma warning restore CS8602
    }

    [Fact]
    public async Task RemoveAuthorizationCodeAsync_WhenConcurrencyExceptionOccurs_LogsWarningAndSwallowsException()
    {
        // Arrange
        var codeHandle = "concurrent_code";
        var code = new AuthorizationCode { CodeHandle = codeHandle, ClientId = "c1", SubjectId = "s1", ExpirationTime = DateTime.UtcNow.AddMinutes(5) };
        _authCodes.Add(code); // Add initially
        var cancellationToken = CancellationToken.None;

        // Simulate finding the code
        _mockContext.Setup(m => m.AuthorizationCodes.FindAsync(new object[] { codeHandle }, cancellationToken))
            .ReturnsAsync(code);
        _mockContext.Setup(m => m.AuthorizationCodes.Remove(code)); // Mock the Remove call

        // Setup SaveChangesAsync to throw DbUpdateConcurrencyException
        _mockContext.Setup(m => m.SaveChangesAsync(cancellationToken))
            .ThrowsAsync(new DbUpdateConcurrencyException("Concurrency conflict", new List<Microsoft.EntityFrameworkCore.Update.IUpdateEntry>()));

        // Act
        // Exception should be swallowed by the store's catch block
        await _store.RemoveAuthorizationCodeAsync(codeHandle, cancellationToken);

        // Assert
        // Verify SaveChangesAsync was called (even though it threw)
        _mockContext.Verify(m => m.SaveChangesAsync(cancellationToken), Times.Once());

        // Verify the warning log message
#pragma warning disable CS8602
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Concurrency conflict removing authorization code")),
                It.IsAny<DbUpdateConcurrencyException>(), // Check that the correct exception type was logged
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
#pragma warning restore CS8602
    }

    // --- Add tests for StoreAuthorizationCodeAsync and GetAuthorizationCodeAsync --- 
    // (Similar structure: test happy path, null/invalid args, exceptions, edge cases like expired codes for Get)

} 