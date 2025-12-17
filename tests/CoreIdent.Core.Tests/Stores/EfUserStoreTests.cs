using System.Security.Claims;
using CoreIdent.Core.Models;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public class EfUserStoreTests : IDisposable
{
    private readonly CoreIdentDbContext _context;
    private readonly EfUserStore _store;

    public EfUserStoreTests()
    {
        var options = new DbContextOptionsBuilder<CoreIdentDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;

        _context = new CoreIdentDbContext(options);
        _context.Database.OpenConnection();
        _context.Database.EnsureCreated();

        _store = new EfUserStore(_context, TimeProvider.System);
    }

    public void Dispose()
    {
        _context.Database.CloseConnection();
        _context.Dispose();
    }

    private static CoreIdentUser CreateTestUser(string username = "test@example.com") => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        UserName = username,
        CreatedAt = DateTime.UtcNow
    };

    [Fact]
    public async Task FindByIdAsync_ReturnsNull_WhenUserDoesNotExist()
    {
        var result = await _store.FindByIdAsync("nonexistent");

        result.ShouldBeNull("should return null for non-existent user");
    }

    [Fact]
    public async Task CreateAsync_And_FindByIdAsync_WorkCorrectly()
    {
        var user = CreateTestUser();

        await _store.CreateAsync(user);
        var result = await _store.FindByIdAsync(user.Id);

        result.ShouldNotBeNull("should find created user");
        result.UserName.ShouldBe(user.UserName, "username should match");
    }

    [Fact]
    public async Task CreateAsync_ThrowsException_WhenUsernameAlreadyExists()
    {
        var user1 = CreateTestUser("test@example.com");
        var user2 = CreateTestUser("test@example.com");

        await _store.CreateAsync(user1);

        await Should.ThrowAsync<DbUpdateException>(
            () => _store.CreateAsync(user2),
            "should throw when creating duplicate username due to unique index");
    }

    [Fact]
    public async Task FindByUsernameAsync_NormalizesAndMatches()
    {
        var user = CreateTestUser("Test@Example.com");
        await _store.CreateAsync(user);

        var result = await _store.FindByUsernameAsync("test@example.com");

        result.ShouldNotBeNull("should find user by normalized username");
        result.Id.ShouldBe(user.Id, "id should match");
    }

    [Fact]
    public async Task UpdateAsync_UpdatesUser()
    {
        var user = CreateTestUser();
        await _store.CreateAsync(user);

        user.UserName = "updated@example.com";
        user.UpdatedAt = DateTime.UtcNow;
        await _store.UpdateAsync(user);

        var result = await _store.FindByIdAsync(user.Id);
        result.ShouldNotBeNull();
        result.UserName.ShouldBe("updated@example.com", "username should be updated");
    }

    [Fact]
    public async Task UpdateAsync_ThrowsException_WhenUserDoesNotExist()
    {
        var user = CreateTestUser();

        await Should.ThrowAsync<InvalidOperationException>(
            () => _store.UpdateAsync(user),
            "should throw when updating non-existent user");
    }

    [Fact]
    public async Task DeleteAsync_RemovesUser()
    {
        var user = CreateTestUser();
        await _store.CreateAsync(user);

        await _store.DeleteAsync(user.Id);

        (await _store.FindByIdAsync(user.Id)).ShouldBeNull("user should be deleted");
    }

    [Fact]
    public async Task DeleteAsync_DoesNotThrow_WhenUserDoesNotExist()
    {
        await Should.NotThrowAsync(
            () => _store.DeleteAsync("nonexistent"),
            "should not throw when deleting non-existent user");
    }

    [Fact]
    public async Task GetClaimsAsync_And_SetClaimsAsync_WorkCorrectly()
    {
        var user = CreateTestUser();
        await _store.CreateAsync(user);

        var claims = new[]
        {
            new Claim("sub", user.Id),
            new Claim("email", user.UserName)
        };

        await _store.SetClaimsAsync(user.Id, claims);
        var result = await _store.GetClaimsAsync(user.Id);

        result.Count.ShouldBe(2, "should return stored claims");
        result.ShouldContain(c => c.Type == "email" && c.Value == user.UserName, "should contain email claim");
    }

    [Fact]
    public async Task GetClaimsAsync_ReturnsEmpty_WhenUserDoesNotExist()
    {
        var claims = await _store.GetClaimsAsync("nonexistent");

        claims.Count.ShouldBe(0, "should return empty claims for missing user");
    }

    [Fact]
    public async Task SetClaimsAsync_ThrowsException_WhenUserDoesNotExist()
    {
        await Should.ThrowAsync<InvalidOperationException>(
            () => _store.SetClaimsAsync("nonexistent", [new Claim("sub", "x")]),
            "should throw when setting claims for missing user");
    }
}
