using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using CoreIdent.Core.Extensions;
using Xunit;

namespace CoreIdent.Integration.Tests
{
    public class CoreIdentOptionsValidatorIntegrationTests
    {
        private IHostBuilder CreateHostBuilder(Action<CoreIdent.Core.Configuration.CoreIdentOptions> configureOptions)
        {
            return new HostBuilder()
                .ConfigureWebHost(webBuilder =>
                {
                    webBuilder.UseTestServer()
                        .ConfigureServices(services =>
                        {
                            services.AddCoreIdent(configureOptions);
                        });
                });
        }

        [Theory]
#pragma warning disable xUnit1012 // allow null InlineData for invalidAudience test
        [InlineData(null)]
#pragma warning restore xUnit1012
        [InlineData("")]
        [InlineData("   ")]
        public void HostStart_InvalidAudience_Missing_ShouldThrow(string invalidAudience)
        {
            var hostBuilder = CreateHostBuilder(opts =>
            {
                opts.Issuer = "https://valid.issuer";
                opts.Audience = invalidAudience;
                opts.SigningKeySecret = new string('a', 32);
            });

            Assert.Throws<OptionsValidationException>(() => hostBuilder.Start());
        }

        [Fact]
        public void HostStart_InvalidAudience_NotUri_ShouldThrow()
        {
            var hostBuilder = CreateHostBuilder(opts =>
            {
                opts.Issuer = "https://valid.issuer";
                opts.Audience = "not-a-uri";
                opts.SigningKeySecret = new string('a', 32);
            });

            Assert.Throws<OptionsValidationException>(() => hostBuilder.Start());
        }

        [Fact]
        public void HostStart_InvalidIssuer_NotUri_ShouldThrow()
        {
            var hostBuilder = CreateHostBuilder(opts =>
            {
                opts.Issuer = "not-a-uri";
                opts.Audience = "https://valid.audience";
                opts.SigningKeySecret = new string('a', 32);
            });

            Assert.Throws<OptionsValidationException>(() => hostBuilder.Start());
        }
    }
}
