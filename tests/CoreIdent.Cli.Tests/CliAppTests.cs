using CoreIdent.Cli;
using Shouldly;

namespace CoreIdent.Cli.Tests;

public sealed class CliAppTests
{
    [Fact]
    public async Task Help_ReturnsZero()
    {
        var exit = await CliApp.RunAsync(["--help"]);
        exit.ShouldBe(0, "Help should return exit code 0");
    }

    [Fact]
    public async Task UnknownCommand_ReturnsOne()
    {
        var exit = await CliApp.RunAsync(["unknown-command"]);
        exit.ShouldBe(1, "Unknown command should return exit code 1");
    }

    [Fact]
    public async Task KeysHelp_ReturnsZero()
    {
        var exit = await CliApp.RunAsync(["keys", "--help"]);
        exit.ShouldBe(0, "keys --help should return exit code 0");
    }

    [Fact]
    public async Task ClientHelp_ReturnsZero()
    {
        var exit = await CliApp.RunAsync(["client", "--help"]);
        exit.ShouldBe(0, "client --help should return exit code 0");
    }

    [Fact]
    public async Task MigrateHelp_ReturnsZero()
    {
        var exit = await CliApp.RunAsync(["migrate", "--help"]);
        exit.ShouldBe(0, "migrate --help should return exit code 0");
    }

    [Fact]
    public async Task Migrate_WithoutConnection_ReturnsOne()
    {
        var exit = await CliApp.RunAsync(["migrate"]);
        exit.ShouldBe(1, "migrate without --connection should return exit code 1");
    }
}
