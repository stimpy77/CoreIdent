using CoreIdent.Core.Configuration;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using CoreIdent.Storage.EntityFrameworkCore.Services;
using CoreIdent.TestHost;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using System.Linq;
using Xunit;

namespace CoreIdent.Integration.Tests;

public class TokenCleanupServiceTests : IntegrationTestBase
{
    [Fact]
    public void AddCoreIdentEntityFrameworkStores_ShouldRegisterCleanupService_ByDefault()
    {
        // Arrange
        var host = ConfigureHost(enableCleanupService: true);
        
        // Act
        var hostedServices = host.Services.GetServices<IHostedService>().ToList();
        
        // Assert
        // Verify that the cleanup service is registered as a hosted service
        var cleanupService = hostedServices.FirstOrDefault(s => s is RefreshTokenCleanupService);
        cleanupService.ShouldNotBeNull();
    }
    
    [Fact]
    public void AddCoreIdentEntityFrameworkStores_ShouldNotRegisterCleanupService_WhenDisabled()
    {
        // Arrange
        var host = ConfigureHost(enableCleanupService: false);
        
        // Act
        var hostedServices = host.Services.GetServices<IHostedService>().ToList();
        
        // Assert
        // Verify that the cleanup service is not registered
        var cleanupService = hostedServices.FirstOrDefault(s => s is RefreshTokenCleanupService);
        cleanupService.ShouldBeNull();
    }
    
    private IHost ConfigureHost(bool enableCleanupService)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        // Add core services
                        services.AddCoreIdent(options => 
                        {
                            options.Issuer = "https://test.coreident.com";
                            options.Audience = "test_api";
                            options.SigningKeySecret = "a_very_secure_test_key_that_is_long_enough_for_testing";
                        });
                        
                        // Add DbContext
                        services.AddDbContext<CoreIdentDbContext>(options => 
                        {
                            options.UseInMemoryDatabase("TokenCleanupTests");
                        });
                        
                        // Add EF Core stores with cleanup service enabled/disabled
                        services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>(enableCleanupService);
                    })
                    .Configure(app => 
                    {
                        // No middleware needed for this test
                    });
            });
            
        return hostBuilder.Start();
    }
} 