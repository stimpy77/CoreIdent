using CoreIdent.Core.Models;
using CoreIdent.Passkeys.Configuration;
using CoreIdent.Passkeys.AspNetIdentity.Services;
using CoreIdent.Passkeys.AspNetIdentity.Stores;
using CoreIdent.Passkeys.Services;
using CoreIdent.Passkeys.Stores;
using CoreIdent.Passkeys.Stores.InMemory;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace CoreIdent.Passkeys.AspNetIdentity.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddPasskeys(this IServiceCollection services, Action<CoreIdentPasskeyOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<CoreIdentPasskeyOptions>();

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<IPasskeyCredentialStore, InMemoryPasskeyCredentialStore>();

        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        services.AddAuthentication()
            .AddCookie(IdentityConstants.TwoFactorUserIdScheme, _ => { });

        var identityBuilder = services.AddIdentityCore<CoreIdentUser>();
        identityBuilder.AddUserStore<CoreIdentIdentityUserStore>();
        identityBuilder.AddSignInManager();

        services.Replace(ServiceDescriptor.Scoped<IUserPasskeyStore<CoreIdentUser>>(sp => (IUserPasskeyStore<CoreIdentUser>)sp.GetRequiredService<IUserStore<CoreIdentUser>>()));

        services.Replace(ServiceDescriptor.Scoped<IUserClaimsPrincipalFactory<CoreIdentUser>, NullUserClaimsPrincipalFactory>());
        services.Replace(ServiceDescriptor.Scoped<IUserConfirmation<CoreIdentUser>, AlwaysConfirmedUserConfirmation<CoreIdentUser>>());

        services.TryAddScoped<IPasskeyService, AspNetIdentityPasskeyService>();

        services.AddOptions<IdentityPasskeyOptions>()
            .Configure<IOptions<CoreIdentPasskeyOptions>>((identityOptions, coreIdentOptions) =>
            {
                var o = coreIdentOptions.Value;
                identityOptions.ServerDomain = o.RelyingPartyId;
                identityOptions.AuthenticatorTimeout = o.ChallengeTimeout;
                identityOptions.ChallengeSize = o.ChallengeSize;
            });

        services.AddOptions<CookieAuthenticationOptions>(IdentityConstants.TwoFactorUserIdScheme);

        return services;
    }
}
