using System.Text.Json;
using System.Xml.Linq;
using CoreIdent.Cli;
using Shouldly;

namespace CoreIdent.Cli.Tests;

public sealed class InitCommandTests : IDisposable
{
    private readonly string _tempDir;

    public InitCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task Init_CreatesAppSettingsJson()
    {
        var csprojPath = Path.Combine(_tempDir, "TestApp.csproj");
        File.WriteAllText(csprojPath, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
            </Project>
            """);

        var exit = await CliApp.RunAsync(["init", "--project", csprojPath]);

        exit.ShouldBe(0);

        var appSettingsPath = Path.Combine(_tempDir, "appsettings.json");
        File.Exists(appSettingsPath).ShouldBeTrue("appsettings.json should be created");

        var json = await File.ReadAllTextAsync(appSettingsPath);
        var doc = JsonDocument.Parse(json);
        doc.RootElement.TryGetProperty("CoreIdent", out var coreIdentSection).ShouldBeTrue();
        coreIdentSection.TryGetProperty("Issuer", out _).ShouldBeTrue();
        coreIdentSection.TryGetProperty("Audience", out _).ShouldBeTrue();
        coreIdentSection.TryGetProperty("Key", out var keySection).ShouldBeTrue();
        keySection.TryGetProperty("Type", out var typeValue).ShouldBeTrue();
        typeValue.GetString().ShouldBe("Symmetric");
        keySection.TryGetProperty("SymmetricKey", out var symKey).ShouldBeTrue();
        symKey.GetString().ShouldNotBeNullOrWhiteSpace();
        symKey.GetString()!.Length.ShouldBe(64); // 32 bytes = 64 hex chars
    }

    [Fact]
    public async Task Init_AddsPackageReferences()
    {
        var csprojPath = Path.Combine(_tempDir, "TestApp.csproj");
        File.WriteAllText(csprojPath, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
            </Project>
            """);

        var exit = await CliApp.RunAsync(["init", "--project", csprojPath]);

        exit.ShouldBe(0);

        var doc = XDocument.Load(csprojPath);
        var packageRefs = doc.Descendants("PackageReference").ToList();

        packageRefs.Any(p => p.Attribute("Include")?.Value == "CoreIdent.Core").ShouldBeTrue();
        packageRefs.Any(p => p.Attribute("Include")?.Value == "CoreIdent.Storage.EntityFrameworkCore").ShouldBeTrue();
    }

    [Fact]
    public async Task Init_FailsIfAppSettingsExistsWithoutForce()
    {
        var csprojPath = Path.Combine(_tempDir, "TestApp.csproj");
        File.WriteAllText(csprojPath, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
            </Project>
            """);

        var appSettingsPath = Path.Combine(_tempDir, "appsettings.json");
        await File.WriteAllTextAsync(appSettingsPath, "{}");

        var exit = await CliApp.RunAsync(["init", "--project", csprojPath]);

        exit.ShouldBe(1, "Should fail when appsettings.json exists without --force");
    }

    [Fact]
    public async Task Init_OverwritesWithForce()
    {
        var csprojPath = Path.Combine(_tempDir, "TestApp.csproj");
        File.WriteAllText(csprojPath, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
            </Project>
            """);

        var appSettingsPath = Path.Combine(_tempDir, "appsettings.json");
        await File.WriteAllTextAsync(appSettingsPath, "{}");

        var exit = await CliApp.RunAsync(["init", "--project", csprojPath, "--force"]);

        exit.ShouldBe(0);

        var json = await File.ReadAllTextAsync(appSettingsPath);
        var doc = JsonDocument.Parse(json);
        doc.RootElement.TryGetProperty("CoreIdent", out _).ShouldBeTrue("Should have CoreIdent section after --force");
    }

    [Fact]
    public async Task Init_FailsIfProjectNotFound()
    {
        var exit = await CliApp.RunAsync(["init", "--project", "/nonexistent/path/Test.csproj"]);

        exit.ShouldBe(1);
    }
}
