using Microsoft.Extensions.DependencyInjection;
using Shouldly;

namespace CoreIdent.Core.Tests.TestUtilities;

/// <summary>
/// Extension methods for testing service registrations with Shouldly.
/// </summary>
public static class ServiceCollectionShouldlyExtensions
{
    /// <summary>
    /// Asserts that the service collection contains a singleton registration of the specified service type.
    /// </summary>
    public static void ShouldContainSingleton<TService>(this IServiceCollection services)
    {
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(TService) && d.Lifetime == ServiceLifetime.Singleton);
        descriptor.ShouldNotBeNull($"Expected singleton registration for {typeof(TService).Name} but none was found.");
    }

    /// <summary>
    /// Asserts that the service collection contains a singleton registration of the specified service type implemented by the specified implementation type.
    /// </summary>
    public static void ShouldContainSingleton<TService, TImplementation>(this IServiceCollection services)
        where TService : notnull
        where TImplementation : TService
    {
        var descriptor = services.FirstOrDefault(d => 
            d.ServiceType == typeof(TService) && 
            d.Lifetime == ServiceLifetime.Singleton);
        
        descriptor.ShouldNotBeNull($"Expected singleton registration for {typeof(TService).Name} but none was found.");
        
        // Verify the implementation by resolving it
        var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<TService>();
        service.ShouldBeOfType<TImplementation>();
    }

    /// <summary>
    /// Asserts that the service collection contains a scoped registration of the specified service type.
    /// </summary>
    public static void ShouldContainScoped<TService>(this IServiceCollection services)
    {
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(TService) && d.Lifetime == ServiceLifetime.Scoped);
        descriptor.ShouldNotBeNull($"Expected scoped registration for {typeof(TService).Name} but none was found.");
    }

    /// <summary>
    /// Asserts that the service collection contains a scoped registration of the specified service type implemented by the specified implementation type.
    /// </summary>
    public static void ShouldContainScoped<TService, TImplementation>(this IServiceCollection services)
        where TService : notnull
        where TImplementation : TService
    {
        var descriptor = services.FirstOrDefault(d => 
            d.ServiceType == typeof(TService) && 
            d.Lifetime == ServiceLifetime.Scoped);
        
        descriptor.ShouldNotBeNull($"Expected scoped registration for {typeof(TService).Name} but none was found.");
        
        // Verify the implementation by resolving it
        var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<TService>();
        service.ShouldBeOfType<TImplementation>();
    }

    /// <summary>
    /// Asserts that the service collection contains a transient registration of the specified service type.
    /// </summary>
    public static void ShouldContainTransient<TService>(this IServiceCollection services)
    {
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(TService) && d.Lifetime == ServiceLifetime.Transient);
        descriptor.ShouldNotBeNull($"Expected transient registration for {typeof(TService).Name} but none was found.");
    }

    /// <summary>
    /// Asserts that the service collection contains a transient registration of the specified service type implemented by the specified implementation type.
    /// </summary>
    public static void ShouldContainTransient<TService, TImplementation>(this IServiceCollection services)
        where TService : notnull
        where TImplementation : TService
    {
        var descriptor = services.FirstOrDefault(d => 
            d.ServiceType == typeof(TService) && 
            d.Lifetime == ServiceLifetime.Transient);
        
        descriptor.ShouldNotBeNull($"Expected transient registration for {typeof(TService).Name} but none was found.");
        
        // Verify the implementation by resolving it
        var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<TService>();
        service.ShouldBeOfType<TImplementation>();
    }
}
