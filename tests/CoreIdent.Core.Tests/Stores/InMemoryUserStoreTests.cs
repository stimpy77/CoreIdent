using System.Security.Claims;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores.InMemory;
using Microsoft.Extensions.Time.Testing;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class InMemoryUserStoreTests
{
    private static CoreIdentUser CreateTestUser(string username = "test@example.com") => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        UserName = username,
        NormalizedUserName = username.ToUpperInvariant(),
        CreatedAt = DateTime.UtcNow
    };

    [Fact]
    public async Task FindByIdAsync_ReturnsNull_WhenIdIsNullOrEmpty()
    {
        var store = new InMemoryUserStore();

        (await store.FindByIdAsync("")).ShouldBeNull("should return null for empty id");
        (await store.FindByIdAsync("   ")).ShouldBeNull("should return null for whitespace id");
        (await store.FindByIdAsync(null!)).ShouldBeNull("should return null for null id");
    }

    [Fact]
    public async Task FindByUsernameAsync_ReturnsNull_WhenUsernameIsNullOrEmpty()
    {
        var store = new InMemoryUserStore();

        (await store.FindByUsernameAsync("")).ShouldBeNull("should return null for empty username");
        (await store.FindByUsernameAsync("   ")).ShouldBeNull("should return null for whitespace username");
        (await store.FindByUsernameAsync(null!)).ShouldBeNull("should return null for null username");
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsNull_WhenUserDoesNotExist()
    {
        var store = new InMemoryUserStore();

        var result = await store.FindByIdAsync("nonexistent");

        result.ShouldBeNull("should return null for non-existent user");
    }

    [Fact]
    public async Task CreateAsync_And_FindByIdAsync_WorkCorrectly()
    {
        var store = new InMemoryUserStore();
        var user = CreateTestUser();

        await store.CreateAsync(user);
        var result = await store.FindByIdAsync(user.Id);

        result.ShouldNotBeNull("should find created user");
        result.UserName.ShouldBe(user.UserName, "username should match");
    }

    [Fact]
    public async Task CreateAsync_AutoGeneratesId_WhenIdIsEmpty()
    {
        var store = new InMemoryUserStore();
        var user = new CoreIdentUser
        {
            Id = "",
            UserName = "test@example.com",
            NormalizedUserName = "TEST@EXAMPLE.COM",
            CreatedAt = DateTime.UtcNow
        };

        await store.CreateAsync(user);

        user.Id.ShouldNotBeNullOrWhiteSpace("user id should be auto-generated");
        (await store.FindByIdAsync(user.Id)).ShouldNotBeNull("user should be persisted with generated id");
    }

    [Fact]
    public async Task CreateAsync_SetsCreatedAt_FromTimeProvider_WhenNotProvided()
    {
        var start = new DateTimeOffset(2030, 01, 02, 03, 04, 05, TimeSpan.Zero);
        var timeProvider = new FakeTimeProvider(start);
        var store = new InMemoryUserStore(timeProvider);

        var user = new CoreIdentUser
        {
            Id = Guid.NewGuid().ToString("N"),
            UserName = "test@example.com",
            NormalizedUserName = "TEST@EXAMPLE.COM"
        };

        await store.CreateAsync(user);

        user.CreatedAt.ShouldBe(timeProvider.GetUtcNow().UtcDateTime, "created timestamp should be taken from injected TimeProvider");
    }

    [Fact]
    public async Task CreateAsync_ThrowsException_WhenUsernameIsNullOrEmpty()
    {
        var store = new InMemoryUserStore();

        await Should.ThrowAsync<ArgumentException>(
            () => store.CreateAsync(new CoreIdentUser { Id = Guid.NewGuid().ToString("N"), UserName = "" }),
            "should throw when username is empty");

        await Should.ThrowAsync<ArgumentException>(
            () => store.CreateAsync(new CoreIdentUser { Id = Guid.NewGuid().ToString("N"), UserName = "   " }),
            "should throw when username is whitespace");
    }

    [Fact]
    public async Task CreateAsync_ThrowsException_WhenUsernameAlreadyExists()
    {
        var store = new InMemoryUserStore();
        var user1 = CreateTestUser("test@example.com");
        var user2 = CreateTestUser("test@example.com");

        await store.CreateAsync(user1);

        await Should.ThrowAsync<InvalidOperationException>(
            () => store.CreateAsync(user2),
            "should throw when creating duplicate username");
    }

    [Fact]
    public async Task CreateAsync_ThrowsException_WhenIdAlreadyExists()
    {
        var store = new InMemoryUserStore();
        var id = Guid.NewGuid().ToString("N");
        var user1 = new CoreIdentUser { Id = id, UserName = "user1@example.com", CreatedAt = DateTime.UtcNow };
        var user2 = new CoreIdentUser { Id = id, UserName = "user2@example.com", CreatedAt = DateTime.UtcNow };

        await store.CreateAsync(user1);

        await Should.ThrowAsync<InvalidOperationException>(
            () => store.CreateAsync(user2),
            "should throw when creating duplicate id");
    }

    [Fact]
    public async Task FindByUsernameAsync_IsCaseInsensitive_And_Normalizes()
    {
        var store = new InMemoryUserStore();
        var user = CreateTestUser("Test@Example.com");

        await store.CreateAsync(user);

        var result = await store.FindByUsernameAsync("test@example.com");

        result.ShouldNotBeNull("should find user by normalized username");
        result.Id.ShouldBe(user.Id, "user id should match");
    }

    [Fact]
    public async Task UpdateAsync_UpdatesUser()
    {
        var store = new InMemoryUserStore();
        var user = CreateTestUser();
        await store.CreateAsync(user);

        user.UserName = "updated@example.com";
        user.NormalizedUserName = "UPDATED@EXAMPLE.COM";
        user.UpdatedAt = DateTime.UtcNow;
        await store.UpdateAsync(user);

        var result = await store.FindByUsernameAsync("updated@example.com");
        result.ShouldNotBeNull("should find updated user");
        result.Id.ShouldBe(user.Id, "id should remain same");
    }

    [Fact]
    public async Task UpdateAsync_ThrowsException_WhenUserDoesNotExist()
    {
        var store = new InMemoryUserStore();
        var user = CreateTestUser();

        await Should.ThrowAsync<InvalidOperationException>(
            () => store.UpdateAsync(user),
            "should throw when updating non-existent user");
    }

    [Fact]
    public async Task UpdateAsync_ThrowsException_WhenUsernameIsNullOrEmpty()
    {
        var store = new InMemoryUserStore();
        var user = CreateTestUser();
        await store.CreateAsync(user);

        user.UserName = "";

        await Should.ThrowAsync<ArgumentException>(
            () => store.UpdateAsync(user),
            "should throw when updating with empty username");
    }

    [Fact]
    public async Task DeleteAsync_RemovesUser()
    {
        var store = new InMemoryUserStore();
        var user = CreateTestUser();
        await store.CreateAsync(user);

        await store.DeleteAsync(user.Id);

        (await store.FindByIdAsync(user.Id)).ShouldBeNull("user should be deleted");
        (await store.FindByUsernameAsync(user.UserName)).ShouldBeNull("user should not be found by username after delete");
    }

    [Fact]
    public async Task DeleteAsync_DoesNotThrow_WhenUserDoesNotExist()
    {
        var store = new InMemoryUserStore();

        await Should.NotThrowAsync(
            () => store.DeleteAsync("nonexistent"),
            "should not throw when deleting non-existent user");
    }

    [Fact]
    public async Task GetClaimsAsync_And_SetClaimsAsync_WorkCorrectly()
    {
        var store = new InMemoryUserStore();
        var user = CreateTestUser();
        await store.CreateAsync(user);

        var claims = new[]
        {
            new Claim("sub", user.Id),
            new Claim("email", user.UserName)
        };

        await store.SetClaimsAsync(user.Id, claims);
        var result = await store.GetClaimsAsync(user.Id);

        result.Count.ShouldBe(2, "should return stored claims");
        result.ShouldContain(c => c.Type == "email" && c.Value == user.UserName, "should contain email claim");
    }

    [Fact]
    public async Task GetClaimsAsync_ReturnsEmpty_WhenUserDoesNotExist()
    {
        var store = new InMemoryUserStore();

        var claims = await store.GetClaimsAsync("nonexistent");

        claims.Count.ShouldBe(0, "should return empty claims for missing user");
    }

    [Fact]
    public async Task SetClaimsAsync_ThrowsException_WhenSubjectIdIsNullOrEmpty()
    {
        var store = new InMemoryUserStore();

        await Should.ThrowAsync<ArgumentException>(
            () => store.SetClaimsAsync("", [new Claim("sub", "x")]),
            "should throw when subject id is empty");

        await Should.ThrowAsync<ArgumentException>(
            () => store.SetClaimsAsync("   ", [new Claim("sub", "x")]),
            "should throw when subject id is whitespace");
    }
}
