using System.Security.Claims;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Testing.Builders;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CoreIdent.Testing.Fixtures;

public abstract class CoreIdentTestFixture : IAsyncLifetime
{
    protected HttpClient Client { get; private set; } = null!;

    protected IServiceProvider Services { get; private set; } = null!;

    private CoreIdentWebApplicationFactory _factory = null!;

    public virtual Task InitializeAsync()
    {
        _factory = new CoreIdentWebApplicationFactory();
        ConfigureFactory(_factory);

        Client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        Services = _factory.Services;

        _factory.EnsureSeeded();

        return SeedDataAsync();
    }

    public virtual Task DisposeAsync()
    {
        Client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    protected virtual void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
    }

    protected virtual Task SeedDataAsync() => Task.CompletedTask;

    protected async Task<CoreIdentUser> CreateUserAsync(Action<UserBuilder>? configure = null, CancellationToken ct = default)
    {
        using var scope = Services.CreateScope();

        var builder = new UserBuilder();
        configure?.Invoke(builder);

        var user = builder.Build();

        if (builder.Password is not null)
        {
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            user.PasswordHash = hasher.HashPassword(user, builder.Password);
        }

        var userStore = scope.ServiceProvider.GetRequiredService<IUserStore>();
        await userStore.CreateAsync(user, ct);

        if (builder.Claims.Count > 0)
        {
            await userStore.SetClaimsAsync(user.Id, builder.Claims, ct);
        }

        return user;
    }

    protected async Task<CoreIdentClient> CreateClientAsync(Action<ClientBuilder>? configure = null, CancellationToken ct = default)
    {
        using var scope = Services.CreateScope();

        var builder = new ClientBuilder();
        configure?.Invoke(builder);

        var client = builder.Build();

        if (!string.IsNullOrWhiteSpace(builder.Secret))
        {
            var hasher = scope.ServiceProvider.GetRequiredService<IClientSecretHasher>();
            client.ClientSecretHash = hasher.HashSecret(builder.Secret);
        }

        var clientStore = scope.ServiceProvider.GetRequiredService<IClientStore>();
        await clientStore.CreateAsync(client, ct);

        return client;
    }

    protected Task AuthenticateAsAsync(CoreIdentUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        Client.DefaultRequestHeaders.Remove("X-Test-User-Id");
        Client.DefaultRequestHeaders.Remove("X-Test-User-Email");

        Client.DefaultRequestHeaders.Add("X-Test-User-Id", user.Id);
        Client.DefaultRequestHeaders.Add("X-Test-User-Email", user.UserName);

        return Task.CompletedTask;
    }
}
