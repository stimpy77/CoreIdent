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
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using CoreIdent.Core.Tests.Utils; // Added
using CoreIdent.Core.Services; // <-- Add this line explicitly
using Microsoft.Extensions.Logging; // <-- Make sure this is present

namespace CoreIdent.Core.Tests.Stores;

/// <summary>
/// Unit tests for EfUserStore, focusing on logic and interaction with DbContext/DbSet mocks.
/// </summary>
public class EfUserStoreUnitTests
{
    private readonly Mock<CoreIdentDbContext> _mockContext;
    private readonly Mock<DbSet<CoreIdentUser>> _mockUserSet;
    private readonly Mock<DbSet<CoreIdentUserClaim>> _mockUserClaimSet;
    private readonly Mock<IPasswordHasher> _mockPasswordHasher;
    private readonly Mock<ILoggerFactory> _mockLoggerFactory; // <-- Add this
    private readonly EfUserStore _userStore;
    private readonly List<CoreIdentUser> _userSource; // In-memory source for mocking DbSet
    private readonly List<CoreIdentUserClaim> _userClaimSource;

    public EfUserStoreUnitTests()
    {
        // Setup in-memory data sources
        _userSource = new List<CoreIdentUser>();
        _userClaimSource = new List<CoreIdentUserClaim>();

        // Mock DbSet<CoreIdentUser> using the helper
        _mockUserSet = MockDbSetHelper.CreateMockDbSet(_userSource);

        // Mock DbSet<CoreIdentUserClaim> using the helper
        _mockUserClaimSet = MockDbSetHelper.CreateMockDbSet(_userClaimSource);

        // Mock CoreIdentDbContext
        var mockContextObject = new Mock<CoreIdentDbContext>(new DbContextOptions<CoreIdentDbContext>());
        mockContextObject.Setup(m => m.Users).Returns(_mockUserSet.Object);
        mockContextObject.Setup(m => m.UserClaims).Returns(_mockUserClaimSet.Object);
        mockContextObject.Setup(m => m.SaveChangesAsync(It.IsAny<CancellationToken>()))
                         .ReturnsAsync(1); // Default success

        // Mock Attach/Update/Remove on the context level if needed (often done on DbSet mock)
        mockContextObject.Setup(m => m.Users.Attach(It.IsAny<CoreIdentUser>()))
                         .Callback<CoreIdentUser>(user => _mockUserSet.Object.Attach(user)); // Delegate to DbSet mock
        mockContextObject.Setup(m => m.Users.Update(It.IsAny<CoreIdentUser>()))
                         .Callback<CoreIdentUser>(user => _mockUserSet.Object.Update(user)); // Delegate to DbSet mock
        mockContextObject.Setup(m => m.Users.Remove(It.IsAny<CoreIdentUser>()))
                         .Callback<CoreIdentUser>(user => _mockUserSet.Object.Remove(user)); // Delegate to DbSet mock

        _mockContext = mockContextObject;

        // Mock IPasswordHasher
        _mockPasswordHasher = new Mock<IPasswordHasher>();

        // Mock ILoggerFactory <-- Add this
        _mockLoggerFactory = new Mock<ILoggerFactory>();
        _mockLoggerFactory.Setup(x => x.CreateLogger(It.IsAny<string>()))
                          .Returns(new Mock<ILogger>().Object); // Return a dummy logger

        // Instantiate the store with the mocked context, hasher, and logger factory <-- Update this line
        _userStore = new EfUserStore(_mockContext.Object, _mockPasswordHasher.Object, _mockLoggerFactory.Object);
    }

    // Removed CreateMockDbSet and GetKeyValue

    // --- Tests Start Here ---

    [Fact]
    public async Task CreateUserAsync_CallsAddAndSaveChangesAsync()
    {
        // Arrange
        var user = new CoreIdentUser { Id = "u1", UserName = "test@test.com" };

        // Act
        var result = await _userStore.CreateUserAsync(user, CancellationToken.None);

        // Assert
        result.ShouldBe(StoreResult.Success);
        _mockUserSet.Verify(m => m.Add(user), Times.Once());
        _mockContext.Verify(m => m.SaveChangesAsync(CancellationToken.None), Times.Once());
    }

    [Fact]
    public async Task CreateUserAsync_ReturnsConflict_OnDbUpdateException()
    {
        // Arrange
        var user = new CoreIdentUser { Id = "u1", UserName = "test@test.com" };
        _mockContext.Setup(m => m.SaveChangesAsync(It.IsAny<CancellationToken>()))
                    .ThrowsAsync(new DbUpdateException("Simulated conflict"));

        // Act
        var result = await _userStore.CreateUserAsync(user, CancellationToken.None);

        // Assert
        result.ShouldBe(StoreResult.Conflict);
        _mockUserSet.Verify(m => m.Add(user), Times.Once());
        _mockContext.Verify(m => m.SaveChangesAsync(CancellationToken.None), Times.Once());
    }

    [Fact]
    public async Task FindUserByIdAsync_CallsFindAsync()
    {
        // Arrange
        var userId = "findme";
        _userSource.Add(new CoreIdentUser { Id = userId, UserName = "found@test.com" });

        // Act
        var result = await _userStore.FindUserByIdAsync(userId, CancellationToken.None);

        // Assert
        result.ShouldNotBeNull();
        result.Id.ShouldBe(userId);
        // Verify FindAsync was called with the correct key
        _mockUserSet.Verify(m => m.FindAsync(It.Is<object[]>(ids => ids.Length == 1 && (string)ids[0] == userId), It.IsAny<CancellationToken>()), Times.Once());
    }

    // --- Claim Management Unit Tests ---

    [Fact]
    public async Task GetClaimsAsync_ReturnsClaimsFromContext()
    {
        // Arrange
        var user = new CoreIdentUser { Id = "userWithClaims" };
        _userClaimSource.AddRange(new List<CoreIdentUserClaim> {
            new CoreIdentUserClaim { UserId = user.Id, ClaimType = "type1", ClaimValue = "val1" },
            new CoreIdentUserClaim { UserId = "otherUser", ClaimType = "type2", ClaimValue = "val2" },
            new CoreIdentUserClaim { UserId = user.Id, ClaimType = "type3", ClaimValue = "val3" }
        });

        // Act
        var claims = await _userStore.GetClaimsAsync(user, CancellationToken.None);

        // Assert
        claims.Count.ShouldBe(2);
        claims.ShouldContain(c => c.Type == "type1" && c.Value == "val1");
        claims.ShouldContain(c => c.Type == "type3" && c.Value == "val3");
    }

    [Fact]
    public async Task AddClaimsAsync_AddsToContextAndSaves()
    {
        // Arrange
        var user = new CoreIdentUser { Id = "addClaimsUser" };
        var claimsToAdd = new List<Claim> { new Claim("add1", "valAdd1") };

        // Act
        await _userStore.AddClaimsAsync(user, claimsToAdd, CancellationToken.None);

        // Assert
        _mockUserClaimSet.Verify(m => m.Add(It.Is<CoreIdentUserClaim>(uc => uc.UserId == user.Id && uc.ClaimType == "add1")), Times.Once());
        _mockContext.Verify(m => m.SaveChangesAsync(CancellationToken.None), Times.Once());
    }

    [Fact]
    public async Task RemoveClaimsAsync_RemovesFromContextAndSaves()
    {
        // Arrange
        var user = new CoreIdentUser { Id = "removeClaimsUser" };
        var claimToRemove = new Claim("remType", "remVal");
        _userClaimSource.Add(new CoreIdentUserClaim { Id = 1, UserId = user.Id, ClaimType = claimToRemove.Type, ClaimValue = claimToRemove.Value });
        _userClaimSource.Add(new CoreIdentUserClaim { Id = 2, UserId = user.Id, ClaimType = "keepType", ClaimValue = "keepVal" });

        // Act
        await _userStore.RemoveClaimsAsync(user, new[] { claimToRemove }, CancellationToken.None);

        // Assert
        // Verify the correct claim entity was targeted for removal
        _mockUserClaimSet.Verify(m => m.RemoveRange(It.Is<IEnumerable<CoreIdentUserClaim>>(list => list.Count() == 1 && list.First().Id == 1)), Times.Once());
        _mockContext.Verify(m => m.SaveChangesAsync(CancellationToken.None), Times.Once());
    }

    [Fact]
    public async Task ReplaceClaimAsync_FindsUpdateAndSaves()
    {
        // Arrange
        var user = new CoreIdentUser { Id = "replaceClaimsUser" };
        var oldClaim = new Claim("oldType", "oldVal");
        var newClaim = new Claim("newType", "newVal");
        var existingClaimEntity = new CoreIdentUserClaim { Id = 5, UserId = user.Id, ClaimType = oldClaim.Type, ClaimValue = oldClaim.Value };
        _userClaimSource.Add(existingClaimEntity);

        // Mock Update on the claim set
        _mockUserClaimSet.Setup(m => m.Update(It.IsAny<CoreIdentUserClaim>()));

        // Act
        await _userStore.ReplaceClaimAsync(user, oldClaim, newClaim, CancellationToken.None);

        // Assert
        // Verify the existing entity was updated in the source list
        existingClaimEntity.ClaimType.ShouldBe(newClaim.Type);
        existingClaimEntity.ClaimValue.ShouldBe(newClaim.Value);
        // Verify Update was called on the DbSet
        _mockUserClaimSet.Verify(m => m.Update(existingClaimEntity), Times.Once());
        _mockContext.Verify(m => m.SaveChangesAsync(CancellationToken.None), Times.Once());
    }

    [Fact]
    public async Task UpdateUserAsync_AttachesUpdatesAndSaves()
    {
        // Arrange
        var initialStamp = Guid.NewGuid().ToString();
        var user = new CoreIdentUser { Id = "updateUser", UserName = "test@test.com", ConcurrencyStamp = initialStamp };
        _userSource.Add(user); // Simulate user already existing

        // Setup mocks for Attach and Update on the user set
        _mockUserSet.Setup(m => m.Attach(user)).Returns((Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry<CoreIdentUser>)null!); // Return type doesn't matter much for mock
        _mockUserSet.Setup(m => m.Update(user)).Returns((Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry<CoreIdentUser>)null!); // Return type doesn't matter much for mock

        var updatedUserName = "updated@test.com";
        user.UserName = updatedUserName; // Simulate a change

        // Act
        var result = await _userStore.UpdateUserAsync(user, CancellationToken.None);

        // Assert
        result.ShouldBe(StoreResult.Success);
        _mockUserSet.Verify(m => m.Attach(user), Times.Once());
        _mockUserSet.Verify(m => m.Update(user), Times.Once());
        _mockContext.Verify(m => m.SaveChangesAsync(CancellationToken.None), Times.Once());
        // Verify the ConcurrencyStamp was updated (done within the store method)
        user.ConcurrencyStamp.ShouldNotBe(initialStamp);
        user.ConcurrencyStamp.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public async Task DeleteUserAsync_AttachesRemovesAndSaves()
    {
        // Arrange
        var user = new CoreIdentUser { Id = "deleteUser", UserName = "delete@test.com" };
        _userSource.Add(user); // Simulate user exists

        // Setup mocks for Attach and Remove on the user set
        _mockUserSet.Setup(m => m.Attach(user)).Returns((Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry<CoreIdentUser>)null!); // Return type doesn't matter much for mock
        _mockUserSet.Setup(m => m.Remove(user)).Callback<CoreIdentUser>(u => _userSource.Remove(u)); // Ensure removal from source list

        // Act
        var result = await _userStore.DeleteUserAsync(user, CancellationToken.None);

        // Assert
        result.ShouldBe(StoreResult.Success);
        _mockUserSet.Verify(m => m.Attach(user), Times.Once());
        _mockUserSet.Verify(m => m.Remove(user), Times.Once());
        _mockContext.Verify(m => m.SaveChangesAsync(CancellationToken.None), Times.Once());
        _userSource.ShouldNotContain(u => u.Id == "deleteUser"); // Verify removed from source
    }

    // --- Simple Property Setters ---

    [Fact]
    public async Task SetPasswordHashAsync_SetsProperty()
    {
        // Arrange
        var user = new CoreIdentUser();
        var hash = "hashed_password";

        // Act
        await _userStore.SetPasswordHashAsync(user, hash, CancellationToken.None);

        // Assert
        user.PasswordHash.ShouldBe(hash);
    }

    [Fact]
    public async Task SetLockoutEndDateAsync_SetsProperty()
    {
        // Arrange
        var user = new CoreIdentUser();
        var lockoutEnd = DateTimeOffset.UtcNow.AddDays(1);

        // Act
        await _userStore.SetLockoutEndDateAsync(user, lockoutEnd, CancellationToken.None);

        // Assert
        user.LockoutEnd.ShouldBe(lockoutEnd);
    }
} 