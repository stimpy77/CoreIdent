using CoreIdent.Core.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace CoreIdent.Adapters.DelegatedUserStore.Extensions;

public static class CoreIdentDelegatedUserStoreExtensions
{
    /// <summary>
    /// Adds the DelegatedUserStore to the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Action to configure the delegates required by DelegatedUserStore.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown if services or configureOptions is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown if required delegates are not configured.</exception>
    public static IServiceCollection AddCoreIdentDelegatedUserStore(
        this IServiceCollection services,
        Action<DelegatedUserStoreOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        // Configure the options
        services.Configure(configureOptions);

        // Add the store implementation, trying not to overwrite existing IUserStore registrations
        services.TryAddScoped<IUserStore, DelegatedUserStore>();

        // Add a validation step to ensure required delegates are set after configuration
        services.AddSingleton<IValidateOptions<DelegatedUserStoreOptions>>(new ValidateDelegatedUserStoreOptions());

        return services;
    }
}

/// <summary>
/// Validator for DelegatedUserStoreOptions to ensure required delegates are provided.
/// </summary>
internal sealed class ValidateDelegatedUserStoreOptions : IValidateOptions<DelegatedUserStoreOptions>
{
    public ValidateOptionsResult Validate(string? name, DelegatedUserStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> missingDelegates = new();

        if (options.FindUserByIdAsync is null)
        {
            missingDelegates.Add(nameof(options.FindUserByIdAsync));
        }
        if (options.FindUserByUsernameAsync is null)
        {
            missingDelegates.Add(nameof(options.FindUserByUsernameAsync));
        }
        if (options.ValidateCredentialsAsync is null)
        {
            missingDelegates.Add(nameof(options.ValidateCredentialsAsync));
        }

        if (missingDelegates.Count > 0)
        {
            return ValidateOptionsResult.Fail($"The following required delegates are missing in {nameof(DelegatedUserStoreOptions)}: {string.Join(", ", missingDelegates)}.");
        }

        return ValidateOptionsResult.Success;
    }
} 