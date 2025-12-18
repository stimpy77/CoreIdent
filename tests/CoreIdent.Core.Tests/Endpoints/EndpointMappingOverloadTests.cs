using CoreIdent.Core.Configuration;
using CoreIdent.Core.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace CoreIdent.Core.Tests.Endpoints;

public sealed class EndpointMappingOverloadTests
{
    [Fact]
    public async Task MapCoreIdentConsentEndpoints_overload_resolves_route_options_from_di()
    {
        using var host = await CreateHostAsync(endpoints => endpoints.MapCoreIdentConsentEndpoints());
        _ = host;
    }

    [Fact]
    public async Task MapCoreIdentUserInfoEndpoint_overload_resolves_route_options_from_di()
    {
        using var host = await CreateHostAsync(endpoints => endpoints.MapCoreIdentUserInfoEndpoint());
        _ = host;
    }

    private static async Task<IHost> CreateHostAsync(Action<IEndpointRouteBuilder> map)
    {
        var builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        services.AddOptions();
                        services.Configure<CoreIdentRouteOptions>(_ => { });
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(map);
                    });
            });

        return await builder.StartAsync();
    }
}
