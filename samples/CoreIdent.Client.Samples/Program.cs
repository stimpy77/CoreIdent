using CoreIdent.Client;
using CoreIdent.Client.Samples.BrowserLaunchers;
using System.Security.Claims;

static void PrintUsage()
{
    Console.WriteLine("CoreIdent.Client.Samples");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  dotnet run --project samples/CoreIdent.Client.Samples -- keycloak [--authority <url>] [--client-id <id>] [--client-secret <secret>] [--redirect-uri <url>] [--post-logout-redirect-uri <url>] [--scopes <space-delimited>] [--dump-claims] [--ci]");
    Console.WriteLine("  dotnet run --project samples/CoreIdent.Client.Samples -- coreident [--authority <url>] [--client-id <id>] [--client-secret <secret>] [--redirect-uri <url>] [--test-user-id <id>] [--test-user-email <email>] [--scopes <space-delimited>] [--dump-claims] [--ci]");
    Console.WriteLine();
    Console.WriteLine("Behavior:");
    Console.WriteLine("  - If 'offline_access' is in scopes and the provider grants a refresh token, the sample will attempt a refresh.");
    Console.WriteLine("  - If end_session_endpoint is advertised and --post-logout-redirect-uri is provided, the sample will attempt logout.");
    Console.WriteLine("  - --ci enables minimal output and non-interactive behavior (intended for headless runs).\n");
}


static void DumpClaims(string title, ClaimsPrincipal? user)
{
    Console.WriteLine(title);

    if (user is null)
    {
        Console.WriteLine("  <none>");
        return;
    }

    foreach (var claim in user.Claims.OrderBy(c => c.Type, StringComparer.Ordinal).ThenBy(c => c.Value, StringComparer.Ordinal))
    {
        Console.WriteLine($"  {claim.Type} = {claim.Value}");
    }
}

static void DumpAccessToken(string? accessToken)
{
    Console.WriteLine("Access Token:");
    if (string.IsNullOrWhiteSpace(accessToken))
    {
        Console.WriteLine("  <none>");
        return;
    }

    if (!TryDumpJwtPayloadClaims(accessToken))
    {
        Console.WriteLine("  <opaque>");
    }
}

static bool TryDumpJwtPayloadClaims(string token)
{
    var parts = token.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (parts.Length != 3)
    {
        return false;
    }

    try
    {
        var payload = parts[1];
        var bytes = Base64UrlDecode(payload);
        using var doc = System.Text.Json.JsonDocument.Parse(bytes);

        foreach (var prop in doc.RootElement.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
        {
            DumpJsonValue(prop.Name, prop.Value);
        }

        return true;
    }
    catch
    {
        return false;
    }
}

static void DumpJsonValue(string name, System.Text.Json.JsonElement value)
{
    switch (value.ValueKind)
    {
        case System.Text.Json.JsonValueKind.Array:
            foreach (var item in value.EnumerateArray())
            {
                DumpJsonValue(name, item);
            }
            break;
        case System.Text.Json.JsonValueKind.Object:
            Console.WriteLine($"  {name} = {value.GetRawText()}");
            break;
        default:
            Console.WriteLine($"  {name} = {value.ToString()}");
            break;
    }
}

static byte[] Base64UrlDecode(string input)
{
    var s = input.Replace('-', '+').Replace('_', '/');
    var padding = s.Length % 4;
    if (padding == 2)
    {
        s += "==";
    }
    else if (padding == 3)
    {
        s += "=";
    }
    else if (padding != 0)
    {
        throw new FormatException("Invalid base64url string.");
    }

    return Convert.FromBase64String(s);
}

static string? GetArg(IReadOnlyList<string> args, string name)
{
    for (var i = 0; i < args.Count - 1; i++)
    {
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
        {
            return args[i + 1];
        }
    }

    return null;
}

static IEnumerable<string> ParseScopes(string? scopes)
{
    if (string.IsNullOrWhiteSpace(scopes))
    {
        return ["openid", "profile", "email"];
    }

    return scopes
        .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.Ordinal);
}

static async Task<int> RunAsync(string[] argv)
{
    if (argv.Length == 0 || argv[0] is "-h" or "--help")
    {
        PrintUsage();
        return 1;
    }

    var mode = argv[0];
    var args = argv.Skip(1).ToArray();

    var ci = args.Any(a => string.Equals(a, "--ci", StringComparison.OrdinalIgnoreCase));
    var dumpClaims = args.Any(a => string.Equals(a, "--dump-claims", StringComparison.OrdinalIgnoreCase));
    void Info(string message)
    {
        if (!ci)
        {
            Console.WriteLine(message);
        }
    }

    var scopeList = ParseScopes(GetArg(args, "--scopes")).ToArray();
    var wantsOfflineAccess = scopeList.Contains("offline_access", StringComparer.Ordinal);

    if (string.Equals(mode, "keycloak", StringComparison.OrdinalIgnoreCase))
    {
        if (ci)
        {
            Console.Error.WriteLine("--ci is not supported for 'keycloak' mode (interactive browser required).");
            return 2;
        }

        var authority = GetArg(args, "--authority") ?? "http://localhost:8080/realms/coreident-dev/";
        var clientId = GetArg(args, "--client-id") ?? "coreident-client";
        var clientSecret = GetArg(args, "--client-secret") ?? "coreident-client-secret";
        var redirectUri = GetArg(args, "--redirect-uri") ?? "http://localhost:7890/callback/";
        var postLogoutRedirectUri = GetArg(args, "--post-logout-redirect-uri");

        var options = new CoreIdentClientOptions
        {
            Authority = authority,
            ClientId = clientId,
            ClientSecret = clientSecret,
            RedirectUri = redirectUri,
            PostLogoutRedirectUri = postLogoutRedirectUri ?? string.Empty,
            Scopes = scopeList,

            // If the provider grants refresh tokens, force the client to try refresh immediately.
            TokenRefreshThreshold = wantsOfflineAccess ? TimeSpan.FromDays(365) : TimeSpan.FromMinutes(5)
        };

        using var client = new CoreIdentClient(options);

        Info($"Fetching discovery from {authority} ...");
        Info("Starting interactive login in your browser...");

        var result = await client.LoginAsync();
        if (!result.IsSuccess)
        {
            Console.Error.WriteLine($"Login failed: {result.Error} {result.ErrorDescription}");
            return 2;
        }

        Info("Login succeeded. Fetching user info (if available)...");
        var user = await client.GetUserAsync();
        if (!ci)
        {
            if (user is not null)
            {
                var sub = user.FindFirst("sub")?.Value;
                var email = user.FindFirst("email")?.Value;
                Console.WriteLine($"User: sub={sub ?? "<none>"}, email={email ?? "<none>"}");

                if (dumpClaims)
                {
                    var idUser = await client.GetValidatedIdTokenUserAsync();
                    var userInfoUser = await client.GetUserInfoAsync();

                    DumpClaims("ID Token Claims:", idUser);
                    DumpClaims("UserInfo Claims:", userInfoUser);
                    DumpClaims("Merged Claims (GetUserAsync):", user);
                }
            }
            else
            {
                Console.WriteLine("UserInfo/ID token claims not available.");
            }
        }

        // Refresh token exercise (only if the provider granted one).
        if (wantsOfflineAccess)
        {
            Info("offline_access requested; attempting refresh (if refresh_token was issued)...");
            var silent = await client.LoginSilentAsync();
            if (!silent.IsSuccess)
            {
                Console.Error.WriteLine($"Refresh exercise failed: {silent.Error} {silent.ErrorDescription}");
                return 3;
            }
        }

        var token = await client.GetAccessTokenAsync();
        if (string.IsNullOrWhiteSpace(token))
        {
            Console.Error.WriteLine("Access token missing.");
            return 4;
        }

        if (!ci && dumpClaims)
        {
            DumpAccessToken(token);
        }

        // Logout exercise (only if provider advertises end_session_endpoint and caller opted in).
        if (!string.IsNullOrWhiteSpace(postLogoutRedirectUri))
        {
            Info("Attempting logout (only runs if end_session_endpoint is advertised)...");
            await client.LogoutAsync();
        }

        Info("OK");
        return 0;
    }

    if (string.Equals(mode, "coreident", StringComparison.OrdinalIgnoreCase))
    {
        var authority = GetArg(args, "--authority") ?? "http://localhost:5080/";
        var clientId = GetArg(args, "--client-id") ?? "coreident-client";
        var clientSecret = GetArg(args, "--client-secret") ?? "coreident-client-secret";
        var redirectUri = GetArg(args, "--redirect-uri") ?? "http://localhost:7890/callback/";

        var testUserId = GetArg(args, "--test-user-id") ?? "user-1";
        var testUserEmail = GetArg(args, "--test-user-email") ?? "alice@example.com";

        var options = new CoreIdentClientOptions
        {
            Authority = authority,
            ClientId = clientId,
            ClientSecret = clientSecret,
            RedirectUri = redirectUri,
            PostLogoutRedirectUri = string.Empty,
            Scopes = scopeList,

            // If a refresh token is present, force the client to try refresh immediately.
            TokenRefreshThreshold = wantsOfflineAccess ? TimeSpan.FromDays(365) : TimeSpan.FromMinutes(5)
        };

        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var http = new HttpClient(handler) { BaseAddress = new Uri(authority, UriKind.Absolute) };
        using var browser = new TestHeaderBrowserLauncher(http, testUserId, testUserEmail);
        using var client = new CoreIdentClient(options, httpClient: http, browserLauncher: browser);

        Info("Running headless authorize -> token exchange against CoreIdent sample host...");
        var result = await client.LoginAsync();
        if (!result.IsSuccess)
        {
            Console.Error.WriteLine($"Login failed: {result.Error} {result.ErrorDescription}");
            return 2;
        }

        var user = await client.GetUserAsync();
        if (!ci && dumpClaims)
        {
            var idUser = await client.GetValidatedIdTokenUserAsync();
            var userInfoUser = await client.GetUserInfoAsync();

            DumpClaims("ID Token Claims:", idUser);
            DumpClaims("UserInfo Claims:", userInfoUser);
            DumpClaims("Merged Claims (GetUserAsync):", user);
        }

        // Refresh token exercise (only if the provider granted one).
        if (wantsOfflineAccess)
        {
            Info("offline_access requested; attempting refresh (if refresh_token was issued)...");
            var silent = await client.LoginSilentAsync();
            if (!silent.IsSuccess)
            {
                Console.Error.WriteLine($"Refresh exercise failed: {silent.Error} {silent.ErrorDescription}");
                return 3;
            }
        }

        var token = await client.GetAccessTokenAsync();
        if (string.IsNullOrWhiteSpace(token))
        {
            Console.Error.WriteLine("Access token missing.");
            return 4;
        }

        if (!ci && dumpClaims)
        {
            DumpAccessToken(token);
        }

        Info("OK");
        return 0;
    }

    Console.Error.WriteLine($"Unknown mode: {mode}");
    PrintUsage();
    return 1;
}

return await RunAsync(args);
