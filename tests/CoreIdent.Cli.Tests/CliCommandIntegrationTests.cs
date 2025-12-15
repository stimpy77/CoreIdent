using System.Text;
using CoreIdent.Cli;
using Shouldly;

namespace CoreIdent.Cli.Tests;

public sealed class CliCommandIntegrationTests
{
    [Fact]
    public async Task KeysGenerateRsa_WritesPemToStdout_AndReturnsZero()
    {
        var originalOut = Console.Out;
        try
        {
            using var sw = new StringWriter();
            Console.SetOut(sw);

            var exit = await CliApp.RunAsync(["keys", "generate", "rsa", "--size", "2048"]);

            exit.ShouldBe(0);

            var output = sw.ToString();
            output.ShouldContain("BEGIN PRIVATE KEY");
            output.ShouldContain("BEGIN PUBLIC KEY");
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public async Task KeysGenerateEcdsa_WritesPemToStdout_AndReturnsZero()
    {
        var originalOut = Console.Out;
        try
        {
            using var sw = new StringWriter();
            Console.SetOut(sw);

            var exit = await CliApp.RunAsync(["keys", "generate", "ecdsa"]);

            exit.ShouldBe(0);

            var output = sw.ToString();
            output.ShouldContain("BEGIN PRIVATE KEY");
            output.ShouldContain("BEGIN PUBLIC KEY");
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public async Task ClientAdd_NonInteractive_Confidential_ReturnsZero_AndPrintsCredentials()
    {
        var originalOut = Console.Out;
        try
        {
            using var sw = new StringWriter();
            Console.SetOut(sw);

            var exit = await CliApp.RunAsync([
                "client", "add",
                "--name", "Test Client",
                "--type", "confidential",
                "--redirect-uri", "https://localhost/callback",
                "--scopes", "openid profile"
            ]);

            exit.ShouldBe(0);

            var output = sw.ToString();
            output.ShouldContain("Client registration");
            output.ShouldContain("client_id:");
            output.ShouldContain("client_secret:");
            output.ShouldContain("C# snippet:");
            output.ShouldContain("await clientStore.CreateAsync");
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public async Task ClientAdd_NonInteractive_Public_ReturnsZero_AndDoesNotPrintClientSecret()
    {
        var originalOut = Console.Out;
        try
        {
            using var sw = new StringWriter();
            Console.SetOut(sw);

            var exit = await CliApp.RunAsync([
                "client", "add",
                "--name", "Test Public Client",
                "--type", "public",
                "--redirect-uri", "https://localhost/callback",
                "--scopes", "openid profile"
            ]);

            exit.ShouldBe(0);

            var output = sw.ToString();
            output.ShouldContain("Client registration");
            output.ShouldContain("client_id:");
            output.ShouldNotContain("client_secret:");
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }
}
