using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public sealed class PasswordlessEmailTemplateRendererTests
{
    [Fact]
    public void Constructor_accepts_null_options()
    {
        // Arrange
        IOptions<PasswordlessEmailOptions>? options = null;
        var environment = new MockHostEnvironment();

        // Act
        var renderer = new PasswordlessEmailTemplateRenderer(options!, environment);

        // Assert - should not throw, constructor accepts null options
        renderer.ShouldNotBeNull();
    }

    [Fact]
    public void Constructor_accepts_null_environment()
    {
        // Arrange
        var options = Options.Create(new PasswordlessEmailOptions());
        IHostEnvironment? environment = null;

        // Act
        var renderer = new PasswordlessEmailTemplateRenderer(options, environment!);

        // Assert - should not throw, constructor accepts null environment
        renderer.ShouldNotBeNull();
    }

    [Fact]
    public async Task RenderAsync_uses_default_template_when_no_template_path_configured()
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

        // Assert
        result.ShouldContain("TestApp");
        result.ShouldContain("https://example.com/verify");
        result.ShouldContain("<!doctype html>");
        result.ShouldContain("<html>");
        
        // Verify the template structure
        result.ShouldContain("Sign in to TestApp");
        result.ShouldContain("<a href=\"https://example.com/verify\">Sign in</a>");
    }

    [Fact]
    public async Task RenderAsync_uses_default_template_when_empty_template_path_configured()
    {
        // Arrange
        var options = Options.Create(new PasswordlessEmailOptions
        {
            EmailTemplatePath = ""
        });
        var environment = new MockHostEnvironment { ApplicationName = "TestApp" };
        var renderer = new PasswordlessEmailTemplateRenderer(options, environment);

        // Act
        var result = await renderer.RenderAsync("test@example.com", "https://example.com/verify");

        // Assert
        result.ShouldContain("TestApp");
        result.ShouldContain("https://example.com/verify");
        
        // Verify the template structure
        result.ShouldContain("Sign in to TestApp");
        result.ShouldContain("<a href=\"https://example.com/verify\">Sign in</a>");
    }

    [Fact]
    public async Task RenderAsync_uses_custom_template_from_absolute_path()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "<html><body>Custom template for {AppName} - {Email} - {VerifyUrl}</body></html>");
            
            var options = Options.Create(new PasswordlessEmailOptions
            {
                EmailTemplatePath = tempFile
            });
            var environment = new MockHostEnvironment { ApplicationName = "TestApp" };
            var renderer = new PasswordlessEmailTemplateRenderer(options, environment);

            // Act
            var result = await renderer.RenderAsync("test@example.com", "https://example.com/verify");

            // Assert
            result.ShouldBe("<html><body>Custom template for TestApp - test@example.com - https://example.com/verify</body></html>");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task RenderAsync_uses_custom_template_from_relative_path()
    {
        // Arrange
        var tempDir = Path.GetTempPath();
        var tempFile = "custom-template.html";
        var fullPath = Path.Combine(tempDir, tempFile);
        
        try
        {
            await File.WriteAllTextAsync(fullPath, "<html><body>Relative template for {AppName} - {Email} - {VerifyUrl}</body></html>");
            
            var options = Options.Create(new PasswordlessEmailOptions
            {
                EmailTemplatePath = tempFile
            });
            var environment = new MockHostEnvironment 
            { 
                ApplicationName = "TestApp",
                ContentRootPath = tempDir
            };
            var renderer = new PasswordlessEmailTemplateRenderer(options, environment);

            // Act
            var result = await renderer.RenderAsync("test@example.com", "https://example.com/verify");

            // Assert
            result.ShouldBe("<html><body>Relative template for TestApp - test@example.com - https://example.com/verify</body></html>");
        }
        finally
        {
            File.Delete(fullPath);
        }
    }

    [Fact]
    public async Task RenderAsync_handles_template_with_placeholders()
    {
        // Arrange
        var options = Options.Create(new PasswordlessEmailOptions
        {
            EmailTemplatePath = null
        });
        var environment = new MockHostEnvironment { ApplicationName = "MyApp" };
        var renderer = new PasswordlessEmailTemplateRenderer(options, environment);

        // Act
        var result = await renderer.RenderAsync("user@domain.com", "https://auth.example.com/login?token=abc123");

        // Assert
        result.ShouldContain("MyApp");
        result.ShouldContain("https://auth.example.com/login?token=abc123");
        
        // Verify the template structure
        result.ShouldContain("Sign in to MyApp");
        result.ShouldContain("<a href=\"https://auth.example.com/login?token=abc123\">Sign in</a>");
    }

    [Fact]
    public async Task RenderAsync_handles_special_characters_in_email_and_url()
    {
        // Arrange
        var options = Options.Create(new PasswordlessEmailOptions
        {
            EmailTemplatePath = null
        });
        var environment = new MockHostEnvironment { ApplicationName = "Test&App" };
        var renderer = new PasswordlessEmailTemplateRenderer(options, environment);

        // Act
        var result = await renderer.RenderAsync("test+user@example.com", "https://example.com/verify?param=value&other=test");

        // Assert
        result.ShouldContain("Test&App");
        result.ShouldContain("https://example.com/verify?param=value&other=test");
        
        // Verify the template structure
        result.ShouldContain("Sign in to Test&App");
        result.ShouldContain("<a href=\"https://example.com/verify?param=value&other=test\">Sign in</a>");
    }

    private sealed class MockHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = Directory.GetCurrentDirectory();
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
