using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public sealed class PasswordlessEmailTemplateRendererDebugTest
{
    [Fact]
    public async Task Debug_template_output()
    {
        // Arrange
        var options = Options.Create(new PasswordlessEmailOptions
        {
            EmailTemplatePath = null
        });
        var environment = new MockHostEnvironment { ApplicationName = "TestApp" };
        var renderer = new PasswordlessEmailTemplateRenderer(options, environment);

        // Act
        var result = await renderer.RenderAsync("test@example.com", "https://example.com/verify");

        // Debug - print the actual result
        Console.WriteLine("=== ACTUAL RESULT ===");
        Console.WriteLine(result);
        Console.WriteLine("=== END RESULT ===");

        // Assert
        result.ShouldNotBeNull();
    }

    private sealed class MockHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = Directory.GetCurrentDirectory();
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
