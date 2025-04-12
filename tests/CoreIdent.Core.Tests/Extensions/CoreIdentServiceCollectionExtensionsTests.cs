using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly; 
using System;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public class CoreIdentServiceCollectionExtensionsTests
{
    // Helper to create a valid configuration action
    private Action<CoreIdentOptions> CreateValidConfigurationAction() => options =>
    {
        options.Issuer = "urn:test:issuer";
        options.Audience = "urn:test:audience";
        options.SigningKeySecret = "a_super_secret_key_longer_than_16_bytes";
        options.AccessTokenLifetime = TimeSpan.FromMinutes(10);
        options.RefreshTokenLifetime = TimeSpan.FromDays(5);
    };

    // Helper to create an invalid configuration action (missing required fields)
    private Action<CoreIdentOptions> CreateInvalidConfigurationAction() => options =>
    {
        // Missing Issuer, Audience, SigningKeySecret
        options.AccessTokenLifetime = TimeSpan.FromMinutes(10);
        options.RefreshTokenLifetime = TimeSpan.FromDays(5);
    };

    [Fact]
    public void AddCoreIdent_WithValidConfiguration_ShouldRegisterServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var configureAction = CreateValidConfigurationAction();

        // Act
        services.AddCoreIdent(configureAction);
        var serviceProvider = services.BuildServiceProvider();

        // Assert - Verify core services are registered and options configured
        serviceProvider.GetService<IOptions<CoreIdentOptions>>().ShouldNotBeNull();
        var options = serviceProvider.GetRequiredService<IOptions<CoreIdentOptions>>().Value;
        options.Issuer.ShouldBe("urn:test:issuer"); // Example option check

        serviceProvider.GetService<IValidateOptions<CoreIdentOptions>>().ShouldNotBeNull().ShouldBeOfType<CoreIdentOptionsValidator>();
        serviceProvider.GetService<IPasswordHasher>().ShouldNotBeNull().ShouldBeOfType<DefaultPasswordHasher>();
        serviceProvider.GetService<IUserStore>().ShouldNotBeNull().ShouldBeOfType<InMemoryUserStore>(); // Check default
        serviceProvider.GetService<ITokenService>().ShouldNotBeNull().ShouldBeOfType<JwtTokenService>();

        // Verify UserStore is Singleton (default)
        var store1 = serviceProvider.GetService<IUserStore>();
        var store2 = serviceProvider.GetService<IUserStore>();
        store1.ShouldBeSameAs(store2);
    }

    [Fact]
    public void AddCoreIdent_NullServices_ShouldThrowArgumentNullException()
    {
        // Arrange
        IServiceCollection? services = null;
        var configureAction = CreateValidConfigurationAction();

        // Act
        #pragma warning disable CS8604 // Possible null reference argument.
        Action act = () => services.AddCoreIdent(configureAction);
        #pragma warning restore CS8604

        // Assert
        Should.Throw<ArgumentNullException>(act).ParamName.ShouldBe("services");
    }

    [Fact]
    public void AddCoreIdent_NullConfigureOptions_ShouldThrowArgumentNullException()
    {
        // Arrange
        var services = new ServiceCollection();
        Action<CoreIdentOptions>? configureAction = null;

        // Act
        #pragma warning disable CS8604 // Possible null reference argument.
        Action act = () => services.AddCoreIdent(configureAction);
        #pragma warning restore CS8604

        // Assert
        Should.Throw<ArgumentNullException>(act).ParamName.ShouldBe("configureOptions");
    }

    [Fact]
    public void AddCoreIdent_WithInvalidConfiguration_ShouldThrowDuringValidationOnStart()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddOptions();

        services.AddCoreIdent(options =>
        {
            // Missing required options
            options.SigningKeySecret = null; // Invalid - make others valid to isolate
            options.Issuer = "test-issuer";
            options.Audience = "test-audience";
            options.AccessTokenLifetime = TimeSpan.FromMinutes(10);
        });

        var serviceProvider = services.BuildServiceProvider();

        // Act & Assert
        // Getting the options value triggers the validation.
        Should.Throw<OptionsValidationException>(() => serviceProvider.GetRequiredService<IOptions<CoreIdentOptions>>().Value)
              .Message.ShouldContain("SigningKeySecret is required.");

        // Optionally check that other valid fields are not mentioned (can be done if needed, but requires capturing the exception)
        // var exception = Should.Throw<OptionsValidationException>(act);
        // exception.Message.ShouldNotContain("Issuer is required.");
        // exception.Message.ShouldNotContain("Audience is required.");
    }

     // TODO: Add test for AddCoreIdent with custom UserStore type if needed
}
