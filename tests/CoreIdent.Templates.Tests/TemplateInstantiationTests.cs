using System.Diagnostics;
using System.Text;
using Shouldly;

namespace CoreIdent.Templates.Tests;

public sealed class TemplateInstantiationTests
{
    private const string Version = "1.0.0";

    [Fact]
    public async Task Templates_CanInstantiateAndBuild()
    {
        var repoRoot = FindRepoRoot();

        var testRoot = Path.Combine(Path.GetTempPath(), "coreident-template-tests", Guid.NewGuid().ToString("N"));
        var feedDir = Path.Combine(testRoot, "feed");
        var hiveDir = Path.Combine(testRoot, "hive");
        var outputDir = Path.Combine(testRoot, "out");

        Directory.CreateDirectory(feedDir);
        Directory.CreateDirectory(hiveDir);
        Directory.CreateDirectory(outputDir);

        await PackAsync(repoRoot, feedDir, "src/CoreIdent.Core/CoreIdent.Core.csproj");
        await PackAsync(repoRoot, feedDir, "src/CoreIdent.Passkeys/CoreIdent.Passkeys.csproj");
        await PackAsync(repoRoot, feedDir, "src/CoreIdent.Storage.EntityFrameworkCore/CoreIdent.Storage.EntityFrameworkCore.csproj");
        await PackAsync(repoRoot, feedDir, "src/CoreIdent.Passwords.AspNetIdentity/CoreIdent.Passwords.AspNetIdentity.csproj");
        await PackAsync(repoRoot, feedDir, "src/CoreIdent.Passkeys.AspNetIdentity/CoreIdent.Passkeys.AspNetIdentity.csproj");
        await PackAsync(repoRoot, feedDir, "src/CoreIdent.Templates/CoreIdent.Templates.csproj");

        var templateNupkg = Path.Combine(feedDir, $"CoreIdent.Templates.{Version}.nupkg");
        File.Exists(templateNupkg).ShouldBeTrue($"Expected template pack at: {templateNupkg}");

        await RunDotNetAsync(repoRoot, hiveDir, new[] { "new", "install", templateNupkg, "--debug:custom-hive", hiveDir });

        await InstantiateAndBuildAsync(repoRoot, feedDir, hiveDir, outputDir,
            shortName: "coreident-api",
            name: "Api_Default",
            args: Array.Empty<string>());

        await InstantiateAndBuildAsync(repoRoot, feedDir, hiveDir, outputDir,
            shortName: "coreident-api",
            name: "Api_NoEf",
            args: new[] { "--useEfCore", "false" });

        await InstantiateAndBuildAsync(repoRoot, feedDir, hiveDir, outputDir,
            shortName: "coreident-api",
            name: "Api_NoPasswordless",
            args: new[] { "--usePasswordless", "false" });

        await InstantiateAndBuildAsync(repoRoot, feedDir, hiveDir, outputDir,
            shortName: "coreident-server",
            name: "Server_Default",
            args: Array.Empty<string>());

        await InstantiateAndBuildAsync(repoRoot, feedDir, hiveDir, outputDir,
            shortName: "coreident-server",
            name: "Server_NoPasskeys",
            args: new[] { "--usePasskeys", "false" });

        await InstantiateAndBuildAsync(repoRoot, feedDir, hiveDir, outputDir,
            shortName: "coreident-api-fsharp",
            name: "ApiFSharp_Default",
            args: Array.Empty<string>());

        await InstantiateAndBuildAsync(repoRoot, feedDir, hiveDir, outputDir,
            shortName: "coreident-api-fsharp",
            name: "ApiFSharp_NoEf",
            args: new[] { "--useEfCore", "false" });

        await InstantiateAndBuildAsync(repoRoot, feedDir, hiveDir, outputDir,
            shortName: "coreident-api-fsharp",
            name: "ApiFSharp_NoPasswordless",
            args: new[] { "--usePasswordless", "false" });
    }

    private static async Task PackAsync(string repoRoot, string feedDir, string csprojRelativePath)
    {
        var csproj = Path.Combine(repoRoot, csprojRelativePath);
        await RunDotNetAsync(repoRoot, hiveDir: null, new[]
        {
            "pack",
            csproj,
            "-c", "Release",
            "-o", feedDir,
            $"/p:PackageVersion={Version}"
        });
    }

    private static async Task InstantiateAndBuildAsync(
        string repoRoot,
        string feedDir,
        string hiveDir,
        string outputRoot,
        string shortName,
        string name,
        string[] args)
    {
        var projectDir = Path.Combine(outputRoot, name);

        var newArgs = new List<string>
        {
            "new",
            shortName,
            "-n", name,
            "--debug:custom-hive", hiveDir,
            "-o", projectDir,
        };
        newArgs.AddRange(args);

        await RunDotNetAsync(repoRoot, hiveDir, newArgs.ToArray());

        var projectFile = Directory.EnumerateFiles(projectDir, "*.*proj", SearchOption.TopDirectoryOnly).Single();

        await RunDotNetAsync(projectDir, hiveDir: null, new[] { "restore", projectFile, "--source", feedDir });
        await RunDotNetAsync(projectDir, hiveDir: null, new[] { "build", projectFile, "-c", "Release", "--no-restore" });
    }

    private static async Task RunDotNetAsync(string workingDir, string? hiveDir, string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = workingDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var proc = Process.Start(psi);
        proc.ShouldNotBeNull();

        var stdout = await proc!.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();

        await proc.WaitForExitAsync();

        if (proc.ExitCode != 0)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"dotnet {string.Join(' ', args)}");
            sb.AppendLine($"Exit code: {proc.ExitCode}");
            sb.AppendLine("stdout:");
            sb.AppendLine(stdout);
            sb.AppendLine("stderr:");
            sb.AppendLine(stderr);

            throw new InvalidOperationException(sb.ToString());
        }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var sln = Path.Combine(dir.FullName, "CoreIdent.sln");
            if (File.Exists(sln))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not locate CoreIdent.sln (repo root)");
    }
}
