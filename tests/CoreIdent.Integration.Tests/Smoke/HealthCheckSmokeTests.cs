using System.Net;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Smoke;

public sealed class HealthCheckSmokeTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Health_check_endpoint_returns_200()
    {
        var response = await Client.GetAsync("/health/check");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Health check endpoint should return 200 OK.");
    }
}
