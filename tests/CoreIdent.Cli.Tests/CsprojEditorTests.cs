using System.Xml.Linq;
using CoreIdent.Cli;
using Shouldly;

namespace CoreIdent.Cli.Tests;

public sealed class CsprojEditorTests : IDisposable
{
    private readonly string _tempDir;

    public CsprojEditorTests()
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
    public void AddPackageReferenceIfMissing_AddsNewPackage()
    {
        var csprojPath = Path.Combine(_tempDir, "Test.csproj");
        File.WriteAllText(csprojPath, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
            </Project>
            """);

        CsprojEditor.AddPackageReferenceIfMissing(csprojPath, "SomePackage", "1.0.0");

        var doc = XDocument.Load(csprojPath);
        var packageRef = doc.Descendants("PackageReference")
            .FirstOrDefault(e => e.Attribute("Include")?.Value == "SomePackage");

        packageRef.ShouldNotBeNull();
        packageRef.Attribute("Version")?.Value.ShouldBe("1.0.0");
    }

    [Fact]
    public void AddPackageReferenceIfMissing_DoesNotDuplicateExistingPackage()
    {
        var csprojPath = Path.Combine(_tempDir, "Test.csproj");
        File.WriteAllText(csprojPath, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="SomePackage" Version="1.0.0" />
              </ItemGroup>
            </Project>
            """);

        CsprojEditor.AddPackageReferenceIfMissing(csprojPath, "SomePackage", "2.0.0");

        var doc = XDocument.Load(csprojPath);
        var packageRefs = doc.Descendants("PackageReference")
            .Where(e => e.Attribute("Include")?.Value == "SomePackage")
            .ToList();

        packageRefs.Count.ShouldBe(1);
        packageRefs[0].Attribute("Version")?.Value.ShouldBe("1.0.0");
    }

    [Fact]
    public void AddPackageReferenceIfMissing_AddsToExistingItemGroup()
    {
        var csprojPath = Path.Combine(_tempDir, "Test.csproj");
        File.WriteAllText(csprojPath, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="ExistingPackage" Version="1.0.0" />
              </ItemGroup>
            </Project>
            """);

        CsprojEditor.AddPackageReferenceIfMissing(csprojPath, "NewPackage", "2.0.0");

        var doc = XDocument.Load(csprojPath);
        var itemGroups = doc.Descendants("ItemGroup").ToList();

        itemGroups.Count.ShouldBe(1);
        itemGroups[0].Elements("PackageReference").Count().ShouldBe(2);
    }
}
