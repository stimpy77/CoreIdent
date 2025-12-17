using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Cli;

public static class CliApp
{
    private static readonly string PackageVersion =
        typeof(CliApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(CliApp).Assembly.GetName().Version?.ToString(3)
        ?? "1.0.0";

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        try
        {
            return args[0] switch
            {
                "init" => await RunInitAsync(args.Skip(1).ToArray()),
                "keys" => await RunKeysAsync(args.Skip(1).ToArray()),
                "client" => await RunClientAsync(args.Skip(1).ToArray()),
                "migrate" => await RunMigrateAsync(args.Skip(1).ToArray()),
                _ => Fail($"Unknown command '{args[0]}'.")
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("CoreIdent CLI");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet coreident <command> [options]");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  init                     Scaffold appsettings.json and add package references");
        Console.WriteLine("  keys generate <rsa|ecdsa> Generate RSA/ECDSA key pair (PEM)");
        Console.WriteLine("  client add               Interactive client registration (outputs snippet)");
        Console.WriteLine("  migrate                  Apply EF Core migrations for CoreIdentDbContext");
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        Console.Error.WriteLine("Run 'dotnet coreident --help' for usage.");
        return 1;
    }

    private static string? GetOption(string[] args, string name)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (!string.Equals(args[i], name, StringComparison.Ordinal))
            {
                continue;
            }

            if (i + 1 >= args.Length)
            {
                return null;
            }

            return args[i + 1];
        }

        return null;
    }

    private static bool HasFlag(string[] args, string name)
    {
        return args.Any(a => string.Equals(a, name, StringComparison.Ordinal));
    }

    private static string Prompt(string prompt, string? defaultValue = null)
    {
        if (!string.IsNullOrWhiteSpace(defaultValue))
        {
            Console.Write($"{prompt} [{defaultValue}]: ");
        }
        else
        {
            Console.Write($"{prompt}: ");
        }

        var input = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(input))
        {
            return defaultValue ?? string.Empty;
        }

        return input.Trim();
    }

    private static async Task<int> RunInitAsync(string[] args)
    {
        var projectPath = GetOption(args, "--project");
        var force = HasFlag(args, "--force");

        if (string.IsNullOrWhiteSpace(projectPath))
        {
            var csprojs = Directory.GetFiles(Environment.CurrentDirectory, "*.csproj", SearchOption.TopDirectoryOnly);
            if (csprojs.Length != 1)
            {
                return Fail("--project is required when the current directory does not contain exactly one .csproj.");
            }

            projectPath = csprojs[0];
        }

        if (!File.Exists(projectPath))
        {
            return Fail($"Project file not found: {projectPath}");
        }

        var appSettingsPath = Path.Combine(Path.GetDirectoryName(projectPath)!, "appsettings.json");
        if (File.Exists(appSettingsPath) && !force)
        {
            return Fail($"{appSettingsPath} already exists. Use --force to overwrite.");
        }

        var symmetricKey = CryptoUtil.GenerateHexSecret(byteCount: 32);

        var doc = new
        {
            CoreIdent = new
            {
                Issuer = "https://issuer.example",
                Audience = "https://resource.example",
                Key = new
                {
                    Type = "Symmetric",
                    SymmetricKey = symmetricKey
                }
            }
        };

        var json = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(appSettingsPath, json);
        Console.WriteLine($"Wrote {appSettingsPath}");

        CsprojEditor.AddPackageReferenceIfMissing(projectPath, "CoreIdent.Core", PackageVersion);
        CsprojEditor.AddPackageReferenceIfMissing(projectPath, "CoreIdent.Storage.EntityFrameworkCore", PackageVersion);
        Console.WriteLine("Updated project file with CoreIdent package references.");

        Console.WriteLine();
        Console.WriteLine("Dev symmetric signing key (do not use in production):");
        Console.WriteLine(symmetricKey);

        return 0;
    }

    private static async Task<int> RunKeysAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            Console.WriteLine("Usage: dotnet coreident keys generate <rsa|ecdsa> [--out <path>] [--size <bits>]");
            return 0;
        }

        if (args.Length < 2 || args[0] != "generate")
        {
            return Fail("Expected: keys generate <rsa|ecdsa>");
        }

        var kind = args[1];
        var outPath = GetOption(args, "--out");

        if (string.Equals(kind, "rsa", StringComparison.OrdinalIgnoreCase))
        {
            var sizeStr = GetOption(args, "--size");
            var size = 2048;
            if (!string.IsNullOrWhiteSpace(sizeStr) && !int.TryParse(sizeStr, out size))
            {
                return Fail("--size must be an integer.");
            }

            var pair = PemKeyGenerator.GenerateRsa(size);
            await WriteKeyPairAsync(pair, outPath, "rsa");
            return 0;
        }

        if (string.Equals(kind, "ecdsa", StringComparison.OrdinalIgnoreCase))
        {
            var pair = PemKeyGenerator.GenerateEcdsaP256();
            await WriteKeyPairAsync(pair, outPath, "ecdsa");
            return 0;
        }

        return Fail("Key type must be 'rsa' or 'ecdsa'.");
    }

    private static async Task WriteKeyPairAsync(PemKeyPair pair, string? outPath, string defaultBaseName)
    {
        if (string.IsNullOrWhiteSpace(outPath))
        {
            Console.WriteLine(pair.PrivateKeyPem);
            Console.WriteLine(pair.PublicKeyPem);
            return;
        }

        var basePath = outPath;
        if (Directory.Exists(basePath))
        {
            basePath = Path.Combine(basePath, defaultBaseName);
        }

        var privatePath = basePath.EndsWith(".pem", StringComparison.OrdinalIgnoreCase)
            ? basePath
            : basePath + ".private.pem";

        var publicPath = basePath.EndsWith(".pem", StringComparison.OrdinalIgnoreCase)
            ? basePath.Replace(".pem", ".public.pem", StringComparison.OrdinalIgnoreCase)
            : basePath + ".public.pem";

        await File.WriteAllTextAsync(privatePath, pair.PrivateKeyPem);
        await File.WriteAllTextAsync(publicPath, pair.PublicKeyPem);

        Console.WriteLine($"Wrote {privatePath}");
        Console.WriteLine($"Wrote {publicPath}");
    }

    private static Task<int> RunClientAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            Console.WriteLine("Usage: dotnet coreident client add");
            return Task.FromResult(0);
        }

        if (args[0] != "add")
        {
            return Task.FromResult(Fail("Expected: client add"));
        }

        var clientName = GetOption(args, "--name") ?? Prompt("Client name", "My Client");
        var clientTypeStr = GetOption(args, "--type") ?? Prompt("Client type (public|confidential)", "confidential");

        var clientType = string.Equals(clientTypeStr, "public", StringComparison.OrdinalIgnoreCase)
            ? ClientType.Public
            : ClientType.Confidential;

        var clientId = GetOption(args, "--client-id");
        if (string.IsNullOrWhiteSpace(clientId))
        {
            clientId = "client-" + Guid.NewGuid().ToString("N");
        }

        var redirectUri = GetOption(args, "--redirect-uri") ?? Prompt("Redirect URI", "https://localhost/callback");
        var scopes = (GetOption(args, "--scopes") ?? Prompt("Scopes (space-separated)", "openid profile")).Split(' ', StringSplitOptions.RemoveEmptyEntries);

        string? clientSecret = null;
        if (clientType == ClientType.Confidential)
        {
            clientSecret = CryptoUtil.GenerateBase64UrlSecret(byteCount: 32);
        }

        var client = new CoreIdentClient
        {
            ClientId = clientId,
            ClientName = clientName,
            ClientType = clientType,
            RedirectUris = [redirectUri],
            AllowedScopes = scopes.ToList(),
            AllowedGrantTypes = [GrantTypes.AuthorizationCode],
            RequirePkce = true,
            Enabled = true,
            CreatedAt = TimeProvider.System.GetUtcNow().UtcDateTime
        };

        if (clientType == ClientType.Confidential)
        {
            client.AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken];
            client.AllowOfflineAccess = scopes.Contains(StandardScopes.OfflineAccess, StringComparer.Ordinal);
        }

        Console.WriteLine();
        Console.WriteLine("Client registration");
        Console.WriteLine($"client_id: {client.ClientId}");
        if (clientSecret is not null)
        {
            Console.WriteLine($"client_secret: {clientSecret}");
        }

        Console.WriteLine();
        Console.WriteLine("C# snippet:");
        Console.WriteLine("var client = new CoreIdentClient");
        Console.WriteLine("{");
        Console.WriteLine($"    ClientId = \"{client.ClientId}\",");
        Console.WriteLine($"    ClientName = \"{client.ClientName}\",");
        Console.WriteLine($"    ClientType = ClientType.{client.ClientType},");
        Console.WriteLine($"    RedirectUris = [\"{redirectUri}\"],");
        Console.WriteLine($"    AllowedScopes = [{string.Join(", ", scopes.Select(s => $"\"{s}\""))}],");
        Console.WriteLine($"    AllowedGrantTypes = [{string.Join(", ", client.AllowedGrantTypes.Select(g => $"\"{g}\""))}],");
        Console.WriteLine($"    RequirePkce = {client.RequirePkce.ToString().ToLowerInvariant()},");
        Console.WriteLine($"    Enabled = {client.Enabled.ToString().ToLowerInvariant()},");
        Console.WriteLine("    CreatedAt = TimeProvider.System.GetUtcNow().UtcDateTime");
        Console.WriteLine("};");
        if (clientSecret is not null)
        {
            Console.WriteLine($"client.ClientSecretHash = hasher.HashSecret(\"{clientSecret}\");");
        }
        Console.WriteLine("await clientStore.CreateAsync(client);");

        return Task.FromResult(0);
    }

    private static async Task<int> RunMigrateAsync(string[] args)
    {
        if (HasFlag(args, "-h") || HasFlag(args, "--help"))
        {
            Console.WriteLine("Usage: dotnet coreident migrate --provider <sqlite|sqlserver|postgres> --connection <connectionString>");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --provider, -p    Database provider: sqlite, sqlserver, or postgres (default: sqlite)");
            Console.WriteLine("  --connection, -c  Connection string for the database");
            return 0;
        }

        var connectionString = GetOption(args, "--connection") ?? GetOption(args, "-c");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return Fail("--connection is required.");
        }

        var providerName = GetOption(args, "--provider") ?? GetOption(args, "-p") ?? "sqlite";
        var provider = ParseDatabaseProvider(providerName);
        if (provider is null)
        {
            return Fail($"Unknown provider '{providerName}'. Supported: sqlite, sqlserver, postgres.");
        }

        var options = BuildDbContextOptions(provider.Value, connectionString);

        await using var db = new CoreIdentDbContext(options);
        try
        {
            await db.Database.MigrateAsync();
            Console.WriteLine($"Database migrated ({provider.Value}).");
        }
        catch (InvalidOperationException)
        {
            await db.Database.EnsureCreatedAsync();
            Console.WriteLine($"Database created ({provider.Value}).");
        }

        return 0;
    }

    private static DatabaseProvider? ParseDatabaseProvider(string name)
    {
        return name.ToLowerInvariant() switch
        {
            "sqlite" => DatabaseProvider.Sqlite,
            "sqlserver" or "mssql" => DatabaseProvider.SqlServer,
            "postgres" or "postgresql" or "npgsql" => DatabaseProvider.PostgreSql,
            _ => null
        };
    }

    private static DbContextOptions<CoreIdentDbContext> BuildDbContextOptions(DatabaseProvider provider, string connectionString)
    {
        var builder = new DbContextOptionsBuilder<CoreIdentDbContext>();

        switch (provider)
        {
            case DatabaseProvider.Sqlite:
                builder.UseSqlite(connectionString);
                break;
            case DatabaseProvider.SqlServer:
                builder.UseSqlServer(connectionString);
                break;
            case DatabaseProvider.PostgreSql:
                builder.UseNpgsql(connectionString);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(provider), provider, "Unsupported database provider.");
        }

        return builder.Options;
    }
}

public enum DatabaseProvider
{
    Sqlite,
    SqlServer,
    PostgreSql
}

public static class CryptoUtil
{
    public static string GenerateHexSecret(int byteCount)
    {
        var bytes = RandomNumberGenerator.GetBytes(byteCount);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string GenerateBase64UrlSecret(int byteCount)
    {
        var bytes = RandomNumberGenerator.GetBytes(byteCount);
        var base64 = Convert.ToBase64String(bytes);
        return base64.TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
