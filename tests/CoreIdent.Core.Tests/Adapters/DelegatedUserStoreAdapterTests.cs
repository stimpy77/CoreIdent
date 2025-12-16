using System.Security.Claims;
using CoreIdent.Adapters.DelegatedUserStore;
using CoreIdent.Adapters.DelegatedUserStore.Extensions;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Shouldly;

namespace CoreIdent.Core.Tests.Adapters;

public sealed class DelegatedUserStoreAdapterTests
{
    [Fact]
    public async Task Missing_required_delegates_fails_validation_on_startup()
    {
        var builder = new HostBuilder()
            .ConfigureServices(services =>
            {
                services.AddLogging();

                services.AddCoreIdent(o =>
                {
                    o.Issuer = "https://issuer.example";
                    o.Audience = "https://api.example";
                });

                services.AddCoreIdentDelegatedUserStore(_ => { });
            });

        using var host = builder.Build();

        await Should.ThrowAsync<OptionsValidationException>(
            () => host.StartAsync(),
            "starting the host should fail when delegated user store delegates are missing");
    }

    [Fact]
    public async Task Delegates_are_invoked_for_find_and_credential_validation()
    {
        var services = new ServiceCollection();

        services.AddCoreIdent(o =>
        {
            o.Issuer = "https://issuer.example";
            o.Audience = "https://api.example";
        });

        string? requestedId = null;
        string? requestedUsername = null;
        CoreIdentUser? validatedUser = null;
        string? validatedPassword = null;

        var user = new CoreIdentUser
        {
            Id = "user-1",
            UserName = "user@example.com"
        };

        services.AddCoreIdentDelegatedUserStore(o =>
        {
            o.FindUserByIdAsync = (id, ct) =>
            {
                requestedId = id;
                return Task.FromResult<CoreIdentUser?>(user);
            };

            o.FindUserByUsernameAsync = (username, ct) =>
            {
                requestedUsername = username;
                return Task.FromResult<CoreIdentUser?>(user);
            };

            o.ValidateCredentialsAsync = (u, password, ct) =>
            {
                validatedUser = u;
                validatedPassword = password;
                return Task.FromResult(string.Equals(password, "pw", StringComparison.Ordinal));
            };

            o.GetClaimsAsync = (subjectId, ct) =>
                Task.FromResult<IReadOnlyList<Claim>>([new Claim("role", "admin")]);
        });

        using var provider = services.BuildServiceProvider();

        var userStore = provider.GetRequiredService<IUserStore>();
        var passwordHasher = provider.GetRequiredService<IPasswordHasher>();

        var byId = await userStore.FindByIdAsync("user-1");
        byId.ShouldNotBeNull("find by id should return the delegated user");
        requestedId.ShouldBe("user-1", "FindUserByIdAsync delegate should be invoked with requested id");
        byId!.PasswordHash.ShouldBe(DelegatedUserStore.PasswordHashPlaceholder, "delegated store must not expose password hashes");

        var byUsername = await userStore.FindByUsernameAsync("user@example.com");
        byUsername.ShouldNotBeNull("find by username should return the delegated user");
        requestedUsername.ShouldBe("user@example.com", "FindUserByUsernameAsync delegate should be invoked with requested username");

        var claims = await userStore.GetClaimsAsync("user-1");
        claims.Count.ShouldBe(1, "GetClaimsAsync should return claims from delegated provider");
        claims.ShouldContain(c => c.Type == "role" && c.Value == "admin", "GetClaimsAsync should contain delegated claim");

        var valid = passwordHasher.VerifyHashedPassword(byUsername, byUsername.PasswordHash!, "pw");
        valid.ShouldBeTrue("password hasher should delegate credential validation");

        validatedUser.ShouldNotBeNull("ValidateCredentialsAsync should be invoked");
        validatedPassword.ShouldBe("pw", "ValidateCredentialsAsync should receive the provided password");
    }
}
