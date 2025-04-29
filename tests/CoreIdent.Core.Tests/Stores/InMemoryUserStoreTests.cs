using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class InMemoryUserStoreTests : IDisposable
{
    private readonly InMemoryUserStore _store;
    private readonly CancellationToken _cancellationToken = CancellationToken.None;
    private CoreIdentUser _testUser;

    public InMemoryUserStoreTests()
    {
        _store = new InMemoryUserStore();
        _testUser = new CoreIdentUser { Id = Guid.NewGuid().ToString(), UserName = "test@example.com", PasswordHash = "hashed_password" };
        _store.CreateUserAsync(_testUser, _cancellationToken).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task CreateUserAsync_WithValidUser_ShouldSucceedAndAddUser()
    {
        var newUser = new CoreIdentUser { Id = Guid.NewGuid().ToString(), UserName = "new@example.com", PasswordHash = "new_hash" };

        var result = await _store.CreateUserAsync(newUser, _cancellationToken);
        var foundUser = await _store.FindUserByIdAsync(newUser.Id, _cancellationToken);

        result.ShouldBe(StoreResult.Success);
        foundUser.ShouldNotBeNull();
        foundUser.Id.ShouldBe(newUser.Id);
        foundUser.UserName.ShouldBe(newUser.UserName);
        foundUser.PasswordHash.ShouldBe(newUser.PasswordHash);
    }

    [Fact]
    public void CreateUserAsync_WithNullUser_ShouldThrowArgumentNullException()
    {
        CoreIdentUser? user = null;

        Should.ThrowAsync<ArgumentNullException>(() => _store.CreateUserAsync(user!, _cancellationToken));
    }

    [Fact]
    public async Task CreateUserAsync_WithDuplicateUserName_ShouldReturnConflict()
    {
        var duplicateUser = new CoreIdentUser { Id = Guid.NewGuid().ToString(), UserName = _testUser.UserName, PasswordHash = "duplicate_hash" };

        var result = await _store.CreateUserAsync(duplicateUser, _cancellationToken);

        result.ShouldBe(StoreResult.Conflict);
    }

    [Fact]
    public async Task CreateUserAsync_WithDuplicateUserId_ShouldReturnConflict()
    {
        var duplicateUser = new CoreIdentUser { Id = _testUser.Id, UserName = "another@example.com", PasswordHash = "duplicate_hash" };

        var result = await _store.CreateUserAsync(duplicateUser, _cancellationToken);

        result.ShouldBe(StoreResult.Conflict);
    }

    [Fact]
    public async Task FindUserByIdAsync_WithExistingId_ShouldReturnUser()
    {
        var existingId = _testUser.Id;

        var foundUser = await _store.FindUserByIdAsync(existingId, _cancellationToken);

        foundUser.ShouldNotBeNull();
        foundUser.Id.ShouldBe(existingId);
        foundUser.UserName.ShouldBe(_testUser.UserName);
    }

    [Fact]
    public async Task FindUserByIdAsync_WithNonExistingId_ShouldReturnNull()
    {
        var nonExistingId = "non-existing-id";

        var foundUser = await _store.FindUserByIdAsync(nonExistingId, _cancellationToken);

        foundUser.ShouldBeNull();
    }

    [Fact]
    public void FindUserByIdAsync_WithNullId_ShouldThrowArgumentNullException()
    {
        string? userId = null;

        Should.ThrowAsync<ArgumentNullException>(() => _store.FindUserByIdAsync(userId!, _cancellationToken));
    }

    [Fact]
    public async Task FindUserByUsernameAsync_WithExistingUserName_ShouldReturnUser()
    {
        var existingUserName = _testUser.UserName;

        var foundUser = await _store.FindUserByUsernameAsync(existingUserName!, _cancellationToken);

        foundUser.ShouldNotBeNull();
        foundUser.UserName.ShouldBe(existingUserName);
        foundUser.Id.ShouldBe(_testUser.Id);
    }

    [Fact]
    public async Task FindUserByUsernameAsync_WithNonExistingUserName_ShouldReturnNull()
    {
        var nonExistingUserName = "non-existing@example.com";

        var foundUser = await _store.FindUserByUsernameAsync(nonExistingUserName, _cancellationToken);

        foundUser.ShouldBeNull();
    }

    [Fact]
    public async Task FindUserByUsernameAsync_WithCaseInsensitiveMatch_ShouldReturnUser()
    {
        var upperCaseUserName = _testUser.UserName!.ToUpperInvariant();

        var foundUser = await _store.FindUserByUsernameAsync(upperCaseUserName, _cancellationToken);

        foundUser.ShouldNotBeNull();
        foundUser.UserName.ShouldBe(_testUser.UserName);
    }

    [Fact]
    public void FindUserByUsernameAsync_WithNullUserName_ShouldThrowArgumentNullException()
    {
        string? userName = null;

        Should.ThrowAsync<ArgumentNullException>(() => _store.FindUserByUsernameAsync(userName!, _cancellationToken));
    }

    [Fact]
    public async Task UpdateUserAsync_WithExistingUser_ShouldSucceedAndUpdateUser()
    {
        var userId = _testUser.Id;
        var userToUpdate = await _store.FindUserByIdAsync(userId, _cancellationToken);
        userToUpdate.ShouldNotBeNull();
        userToUpdate!.PasswordHash = "updated_hash";
        var originalUserName = userToUpdate.UserName;

        var result = await _store.UpdateUserAsync(userToUpdate, _cancellationToken);
        var updatedUser = await _store.FindUserByIdAsync(userId, _cancellationToken);

        result.ShouldBe(StoreResult.Success);
        updatedUser.ShouldNotBeNull();
        updatedUser.Id.ShouldBe(userId);
        updatedUser.PasswordHash.ShouldBe("updated_hash");
        updatedUser.UserName.ShouldBe(originalUserName);
    }

    [Fact]
    public async Task UpdateUserAsync_WithNonExistingUser_ShouldReturnFailure()
    {
        var nonExistingUser = new CoreIdentUser { Id = "non-existing-id", UserName = "non@example.com", PasswordHash = "hash" };

        var result = await _store.UpdateUserAsync(nonExistingUser, _cancellationToken);

        result.ShouldBe(StoreResult.Failure);
    }

    [Fact]
    public void UpdateUserAsync_WithNullUser_ShouldThrowArgumentNullException()
    {
        CoreIdentUser? user = null;

        Should.ThrowAsync<ArgumentNullException>(() => _store.UpdateUserAsync(user!, _cancellationToken));
    }

    [Fact]
    public async Task DeleteUserAsync_WithExistingUser_ShouldSucceedAndRemoveUser()
    {
        var userId = _testUser.Id;
        var userToDelete = await _store.FindUserByIdAsync(userId, _cancellationToken);
        userToDelete.ShouldNotBeNull();

        var result = await _store.DeleteUserAsync(userToDelete!, _cancellationToken);
        var foundUser = await _store.FindUserByIdAsync(userId, _cancellationToken);
        var foundUserByName = await _store.FindUserByUsernameAsync(_testUser.UserName!, _cancellationToken);

        result.ShouldBe(StoreResult.Success);
        foundUser.ShouldBeNull();
        foundUserByName.ShouldBeNull();
    }

    [Fact]
    public async Task DeleteUserAsync_WithNonExistingUser_ShouldReturnFailure()
    {
        var nonExistingUser = new CoreIdentUser { Id = "non-existing-id", UserName = "non@example.com", PasswordHash = "hash" };

        var result = await _store.DeleteUserAsync(nonExistingUser, _cancellationToken);

        result.ShouldBe(StoreResult.Failure);
    }

    [Fact]
    public void DeleteUserAsync_WithNullUser_ShouldThrowArgumentNullException()
    {
        CoreIdentUser? user = null;

        Should.ThrowAsync<ArgumentNullException>(() => _store.DeleteUserAsync(user!, _cancellationToken));
    }

    [Fact]
    public async Task ConcurrentOperations_ShouldMaintainConsistency()
    {
        var store = new InMemoryUserStore();
        var user1 = new CoreIdentUser { Id = "c1", UserName = "con1@example.com", PasswordHash = "h1" };
        var user2 = new CoreIdentUser { Id = "c2", UserName = "con2@example.com", PasswordHash = "h2" };

        var createTask1 = store.CreateUserAsync(user1, _cancellationToken);
        var createTask2 = store.CreateUserAsync(user2, _cancellationToken);
        await Task.WhenAll(createTask1, createTask2);

        var findTask1 = store.FindUserByIdAsync(user1.Id, _cancellationToken);
        var findTask2 = store.FindUserByUsernameAsync(user2.UserName!, _cancellationToken);
        var findTask3 = store.FindUserByIdAsync("nonexistent", _cancellationToken);
        await Task.WhenAll(findTask1, findTask2, findTask3);

        var foundUser1 = await findTask1;
        var foundUser2 = await findTask2;
        var foundUser3 = await findTask3;

        var deleteUser1Task = store.DeleteUserAsync(user1, _cancellationToken);
        var deleteResult = await deleteUser1Task;
        var findDeletedTask = store.FindUserByIdAsync(user1.Id, _cancellationToken);
        var foundDeletedUser = await findDeletedTask;

        (await createTask1).ShouldBe(StoreResult.Success);
        (await createTask2).ShouldBe(StoreResult.Success);

        foundUser1.ShouldNotBeNull();
        foundUser1!.Id.ShouldBe(user1.Id);
        foundUser2.ShouldNotBeNull();
        foundUser2!.UserName.ShouldBe(user2.UserName);
        foundUser3.ShouldBeNull();

        deleteResult.ShouldBe(StoreResult.Success);
        foundDeletedUser.ShouldBeNull();
    }
}
