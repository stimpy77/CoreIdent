using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Tests.Infrastructure;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Shouldly; // Using Shouldly for assertions
using System.Threading.Tasks;
using Xunit;
using System.Security.Claims;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Threading; // Added for CancellationToken

namespace CoreIdent.Core.Tests.Stores;

public class EfUserStoreTests : SqliteInMemoryTestBase // Inherit from the base class
{
    private readonly EfUserStore _userStore;

    public EfUserStoreTests()
    {
        // DbContext is initialized by the base class constructor
        _userStore = new EfUserStore(DbContext);
    }

    // --- CreateUserAsync Tests ---

    [Fact]
    public async Task CreateUserAsync_ShouldAddUser_WhenValidUserProvided()
    {
        // Arrange
        var user = new CoreIdentUser { UserName = "test@example.com", NormalizedUserName = "TEST@EXAMPLE.COM" };

        // Act
        var result = await _userStore.CreateUserAsync(user, CancellationToken.None);
        var foundUser = await DbContext.Users.FindAsync(new object[] { user.Id }, CancellationToken.None);

        // Assert
        result.ShouldBe(StoreResult.Success);
        foundUser.ShouldNotBeNull();
        foundUser.Id.ShouldBe(user.Id);
        foundUser.UserName.ShouldBe("test@example.com");
        foundUser.NormalizedUserName.ShouldBe("TEST@EXAMPLE.COM");
    }

    [Fact]
    public async Task CreateUserAsync_ShouldReturnConflict_WhenUsernameExists()
    {
        // Arrange
        var existingUser = new CoreIdentUser { UserName = "test@example.com", NormalizedUserName = "TEST@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(existingUser, CancellationToken.None);
        var newUser = new CoreIdentUser { UserName = "test@example.com", NormalizedUserName = "TEST@EXAMPLE.COM" }; // Same normalized username

        // Act
        var result = await _userStore.CreateUserAsync(newUser, CancellationToken.None);

        // Assert
        result.ShouldBe(StoreResult.Conflict);
        DbContext.Users.Count().ShouldBe(1); // Only the first user should exist
    }

    // --- FindUserByIdAsync Tests ---

    [Fact]
    public async Task FindUserByIdAsync_ShouldReturnUser_WhenUserExists()
    {
        // Arrange
        var user = new CoreIdentUser { UserName = "findbyid@example.com", NormalizedUserName = "FINDBYID@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(user, CancellationToken.None);

        // Act
        var foundUser = await _userStore.FindUserByIdAsync(user.Id, CancellationToken.None);

        // Assert
        foundUser.ShouldNotBeNull();
        foundUser.Id.ShouldBe(user.Id);
        foundUser.UserName.ShouldBe(user.UserName);
    }

    [Fact]
    public async Task FindUserByIdAsync_ShouldReturnNull_WhenUserDoesNotExist()
    {
        // Arrange
        var nonExistentId = Guid.NewGuid().ToString();

        // Act
        var foundUser = await _userStore.FindUserByIdAsync(nonExistentId, CancellationToken.None);

        // Assert
        foundUser.ShouldBeNull();
    }

    // --- FindUserByUsernameAsync Tests ---

    [Fact]
    public async Task FindUserByUsernameAsync_ShouldReturnUser_WhenUserExists()
    {
        // Arrange
        var normalizedUsername = "FINDBYUSERNAME@EXAMPLE.COM";
        var user = new CoreIdentUser { UserName = "findbyusername@example.com", NormalizedUserName = normalizedUsername };
        await _userStore.CreateUserAsync(user, CancellationToken.None);

        // Act
        var foundUser = await _userStore.FindUserByUsernameAsync(normalizedUsername, CancellationToken.None);

        // Assert
        foundUser.ShouldNotBeNull();
        foundUser.Id.ShouldBe(user.Id);
        foundUser.NormalizedUserName.ShouldBe(normalizedUsername);
    }

    [Fact]
    public async Task FindUserByUsernameAsync_ShouldReturnNull_WhenUserDoesNotExist()
    {
        // Arrange
        var nonExistentUsername = "DOESNOTEXIST@EXAMPLE.COM";

        // Act
        var foundUser = await _userStore.FindUserByUsernameAsync(nonExistentUsername, CancellationToken.None);

        // Assert
        foundUser.ShouldBeNull();
    }

    // --- UpdateUserAsync Tests ---
    [Fact]
    public async Task UpdateUserAsync_ShouldUpdateUserData()
    {
        // Arrange
        var user = new CoreIdentUser { UserName = "update@example.com", NormalizedUserName = "UPDATE@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(user, CancellationToken.None);
        // Capture the concurrency stamp *after* creation (before update)
        var originalStamp = user.ConcurrencyStamp;

        user.PasswordHash = "newHash";
        user.LockoutEnd = DateTimeOffset.UtcNow.AddDays(1);

        // Act
        var result = await _userStore.UpdateUserAsync(user, CancellationToken.None);
        // Fetch a fresh copy from the database, ignoring the DbContext cache
        var updatedUser = await DbContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == user.Id, CancellationToken.None);

        // Assert
        result.ShouldBe(StoreResult.Success);
        updatedUser.ShouldNotBeNull("User should exist after update.");
        updatedUser.PasswordHash.ShouldBe("newHash");
        updatedUser.LockoutEnd.ShouldNotBeNull();
        // Assert that the stamp fetched from DB after update is different from the original one
        updatedUser.ConcurrencyStamp.ShouldNotBeNullOrEmpty();
        updatedUser.ConcurrencyStamp.ShouldNotBe(originalStamp, "Concurrency stamp should change on update.");
    }

    // --- DeleteUserAsync Tests ---
    [Fact]
    public async Task DeleteUserAsync_ShouldRemoveUser()
    {
        // Arrange
        var user = new CoreIdentUser { UserName = "delete@example.com", NormalizedUserName = "DELETE@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(user, CancellationToken.None);

        // Act
        var result = await _userStore.DeleteUserAsync(user, CancellationToken.None);
        var foundUser = await DbContext.Users.FindAsync(new object[] { user.Id }, CancellationToken.None);

        // Assert
        result.ShouldBe(StoreResult.Success);
        foundUser.ShouldBeNull();
    }

    // --- Claim Management Tests ---

    [Fact]
    public async Task AddClaimsAsync_And_GetClaimsAsync_ShouldWorkCorrectly()
    {
        // Arrange
        var user = new CoreIdentUser { UserName = "claims@example.com", NormalizedUserName = "CLAIMS@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(user, CancellationToken.None);
        var claimsToAdd = new List<Claim>
        {
            new Claim("test_type1", "value1"),
            new Claim("test_type2", "value2")
        };

        // Act
        await _userStore.AddClaimsAsync(user, claimsToAdd, CancellationToken.None);
        var retrievedClaims = await _userStore.GetClaimsAsync(user, CancellationToken.None);

        // Assert
        retrievedClaims.Count.ShouldBe(2);
        retrievedClaims.ShouldContain(c => c.Type == "test_type1" && c.Value == "value1");
        retrievedClaims.ShouldContain(c => c.Type == "test_type2" && c.Value == "value2");
    }

    [Fact]
    public async Task RemoveClaimsAsync_ShouldRemoveSpecificClaims()
    {
        // Arrange
        var user = new CoreIdentUser { UserName = "removeclaims@example.com", NormalizedUserName = "REMOVECLAIMS@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(user, CancellationToken.None);
        var claimsToAdd = new List<Claim>
        {
            new Claim("test_type1", "value1"),
            new Claim("test_type2", "value2"),
            new Claim("test_type3", "value3")
        };
        await _userStore.AddClaimsAsync(user, claimsToAdd, CancellationToken.None);
        var claimsToRemove = new List<Claim>
        {
            new Claim("test_type1", "value1"),
            new Claim("test_type3", "value3")
        };

        // Act
        await _userStore.RemoveClaimsAsync(user, claimsToRemove, CancellationToken.None);
        var remainingClaims = await _userStore.GetClaimsAsync(user, CancellationToken.None);

        // Assert
        remainingClaims.Count.ShouldBe(1);
        remainingClaims.Single().Type.ShouldBe("test_type2");
        remainingClaims.Single().Value.ShouldBe("value2");
    }

    [Fact]
    public async Task ReplaceClaimAsync_ShouldModifyExistingClaim()
    {
        // Arrange
        var user = new CoreIdentUser { UserName = "replaceclaim@example.com", NormalizedUserName = "REPLACECLAIM@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(user, CancellationToken.None);
        var originalClaim = new Claim("original_type", "original_value");
        await _userStore.AddClaimsAsync(user, new[] { originalClaim }, CancellationToken.None);
        var newClaim = new Claim("new_type", "new_value");

        // Act
        await _userStore.ReplaceClaimAsync(user, originalClaim, newClaim, CancellationToken.None);
        var updatedClaims = await _userStore.GetClaimsAsync(user, CancellationToken.None);

        // Assert
        updatedClaims.Count.ShouldBe(1);
        updatedClaims.Single().Type.ShouldBe("new_type");
        updatedClaims.Single().Value.ShouldBe("new_value");
    }

    [Fact]
    public async Task GetUsersForClaimAsync_ShouldReturnUsersWithClaim()
    {
        // Arrange
        var claim = new Claim("role", "admin");
        var user1 = new CoreIdentUser { UserName = "admin1@example.com", NormalizedUserName = "ADMIN1@EXAMPLE.COM" };
        var user2 = new CoreIdentUser { UserName = "user@example.com", NormalizedUserName = "USER@EXAMPLE.COM" };
        var user3 = new CoreIdentUser { UserName = "admin2@example.com", NormalizedUserName = "ADMIN2@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(user1, CancellationToken.None);
        await _userStore.CreateUserAsync(user2, CancellationToken.None);
        await _userStore.CreateUserAsync(user3, CancellationToken.None);
        await _userStore.AddClaimsAsync(user1, new[] { claim }, CancellationToken.None);
        await _userStore.AddClaimsAsync(user3, new[] { claim }, CancellationToken.None);

        // Act
        var usersWithClaim = await _userStore.GetUsersForClaimAsync(claim, CancellationToken.None);

        // Assert
        usersWithClaim.Count.ShouldBe(2);
        usersWithClaim.Select(u => u.Id).ShouldContain(user1.Id);
        usersWithClaim.Select(u => u.Id).ShouldContain(user3.Id);
        usersWithClaim.Select(u => u.Id).ShouldNotContain(user2.Id);
    }

    // --- Lockout Tests ---
    // Basic tests; relies on UpdateUserAsync to persist changes from Increment/Reset/Set methods
    [Fact]
    public async Task LockoutMethods_ShouldUpdateProperties_InMemory()
    {
        // Arrange
        var user = new CoreIdentUser { UserName = "lockout@example.com", NormalizedUserName = "LOCKOUT@EXAMPLE.COM" };
        await _userStore.CreateUserAsync(user, CancellationToken.None);

        // Act & Assert - Increment
        var count = await _userStore.IncrementAccessFailedCountAsync(user, CancellationToken.None);
        count.ShouldBe(1);
        user.AccessFailedCount.ShouldBe(1);

        // Act & Assert - Reset
        await _userStore.ResetAccessFailedCountAsync(user, CancellationToken.None);
        user.AccessFailedCount.ShouldBe(0);

        // Act & Assert - SetLockoutEnd
        var lockoutEnd = DateTimeOffset.UtcNow.AddMinutes(5);
        await _userStore.SetLockoutEndDateAsync(user, lockoutEnd, CancellationToken.None);
        user.LockoutEnd.ShouldBe(lockoutEnd);

        // Act & Assert - SetLockoutEnabled
        await _userStore.SetLockoutEnabledAsync(user, true, CancellationToken.None);
        user.LockoutEnabled.ShouldBeTrue();

        // Important: Assert these changes are persisted AFTER calling UpdateUserAsync
        var updateResult = await _userStore.UpdateUserAsync(user, CancellationToken.None);
        updateResult.ShouldBe(StoreResult.Success);

        var persistedUser = await _userStore.FindUserByIdAsync(user.Id, CancellationToken.None);
        persistedUser.ShouldNotBeNull();
        persistedUser.AccessFailedCount.ShouldBe(0); // Last state before UpdateUserAsync
        persistedUser.LockoutEnd.ShouldBe(lockoutEnd);
        persistedUser.LockoutEnabled.ShouldBeTrue();
    }

} 