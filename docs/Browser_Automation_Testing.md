# Browser Automation Testing Infrastructure

This document describes the browser automation testing infrastructure for CoreIdent client libraries and E2E tests.

## Overview

CoreIdent uses **Playwright** as the primary browser automation tool for E2E testing. This provides deterministic, reliable testing of redirect-based OAuth/OIDC flows.

## Testing Tiers

| Tier | Type | Description | When to Run |
|------|------|-------------|-------------|
| 1 | Unit Tests | Pure logic: PKCE, URL building, token parsing, claim merging | Every PR |
| 2 | Headless Integration | Real HTTP against local CoreIdent test host; no real browser UI | Every PR |
| 3 | Browser E2E | Playwright-driven; real redirect + callback | Nightly + main branch |

## Prerequisites

### Local Development

1. **.NET 10 SDK** - CoreIdent requires .NET 10
2. **Playwright Browsers** - Install via:
   ```bash
   cd tests/CoreIdent.Testing
   dotnet playwright install
   ```
3. **Available Ports** - Tests use ports 5000-5010 by default

### CI Requirements

```yaml
# GitHub Actions Example
jobs:
  browser-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 10.0.x
      - name: Install Playwright
        run: dotnet playwright install --with-deps chromium
      - name: Run Tier 3 tests
        run: dotnet test CoreIdent.Client.Tests --filter "Category=E2E"
```

## Project Structure

```
tests/CoreIdent.Testing/
├── Host/
│   └── CoreIdentTestHost.cs          # Test server helpers (in-proc or external)
├── Http/
│   └── HttpAssertionExtensions.cs     # HTTP assertion helpers
├── Browser/
│   ├── PlaywrightFixture.cs          # Playwright fixture with diagnostics
│   └── OAuthFlowHelpers.cs           # OAuth/OIDC flow helpers
├── Fixtures/
│   ├── CoreIdentTestFixture.cs       # Base fixture for integration tests
│   └── CoreIdentWebApplicationFactory.cs
└── ...
```

## Usage Examples

### Creating a Test Host

```csharp
using var factory = CoreIdentTestHost.CreateFactory(services =>
{
    services.Configure<CoreIdentOptions>(options =>
    {
        options.Issuer = "https://test-auth.example.com";
        options.Audience = "test-api";
    });
});

var client = factory.CreateClient();
factory.EnsureSeeded();
```

### Running Browser E2E Tests

```csharp
public class OAuthFlowTests : PlaywrightTestBase
{
    public OAuthFlowTests(PlaywrightFixture fixture) : base(fixture) { }

    [Fact]
    public async Task AuthorizationCodeFlow_WithPkce_Succeeds()
    {
        // Arrange
        var clientId = "e2e-test-client";
        var scopes = new[] { "openid", "profile" };
        var codeVerifier = OAuthFlowHelpers.GenerateCodeVerifier();
        var codeChallenge = OAuthFlowHelpers.GenerateCodeChallenge(codeVerifier);
        var state = OAuthFlowHelpers.GenerateState();

        using var listener = new CallbackListener();
        listener.Start();
        var redirectUri = listener.RedirectUri;

        // Act
        var authUrl = OAuthFlowHelpers.BuildAuthorizationUrl(
            authorizationEndpoint: "https://test.example.com/auth/authorize",
            clientId: clientId,
            redirectUri: redirectUri,
            scopes: scopes,
            state: state,
            codeChallenge: codeChallenge
        );

        await GoToAsync(authUrl);
        // ... complete login flow in browser ...

        var (url, parameters) = await listener.WaitForCallbackAsync();

        // Assert
        parameters.ShouldContainKey("code");
        parameters["state"].ShouldBe(state);
    }
}
```

## CI Configuration

### GitHub Actions Workflow

```yaml
name: Browser Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Nightly
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  tier1-2-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 10.0.x
      - run: dotnet restore
      - run: dotnet build --no-restore
      - run: dotnet test CoreIdent.Core.Tests --no-build
      - run: dotnet test CoreIdent.Integration.Tests --no-build
      - run: dotnet test CoreIdent.Client.Tests --filter "Category!=E2E" --no-build

  tier3-browser-tests:
    needs: tier1-2-tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 10.0.x
      - name: Install Playwright
        run: dotnet playwright install --with-deps chromium
      - run: dotnet restore
      - run: dotnet build --no-restore
      - run: dotnet test CoreIdent.Client.Tests --filter "Category=E2E" --no-build
        env:
          PLAYWRIGHT_TRACES: true
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: playwright-traces
          path: playwright-traces/
```

## Diagnostic Output

On test failure, Playwright automatically captures:

1. **Screenshots** - `playwright-screenshots/{TestClass}-{Timestamp}.png`
2. **Traces** - `playwright-traces/{TestClass}-{Timestamp}.zip`
3. **Console Logs** - Available in test output

Configure diagnostic paths in `PlaywrightFixture.cs`:

```csharp
public async Task<IBrowserContext> CreateContextAsync(
    string traceName,
    bool captureScreenshots = true,
    bool captureTraces = true,
    string? screenshotsDir = null,
    string? tracesDir = null)
```

## Timeouts

Default timeouts are configured for CI reliability:

- **Navigation**: 30 seconds
- **Element Wait**: 10 seconds
- **Callback Wait**: 5 minutes
- **Overall Test**: 10 minutes

Increase timeouts for slower environments:

```csharp
Page.DefaultTimeout = 60000; // 60 seconds
```

## Troubleshooting

### Port Conflicts

Tests use ports 5000-5010. To use different ports:

```csharp
using var listener = new CallbackListener(port: 8080, path: "/callback");
```

### Playwright Installation

If Playwright browsers are missing:

```bash
# Linux
sudo apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2

# macOS
brew install playwright

# Windows
dotnet playwright install
```

### Headless Mode Issues

Some authentication flows may require headed mode:

```csharp
Browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
{
    Headless = false,  // headed mode
    Channel = "chromium"
});
```

## Security Considerations

- **Never log tokens or secrets** in E2E tests
- **Use test credentials only** - never real user accounts
- **Isolate test data** - use in-memory SQLite databases
- **Clean up on completion** - dispose of browser contexts and listeners

## See Also

- [Playwright Documentation](https://playwright.dev/docs/intro)
- [CoreIdent DEVPLAN.md - Feature 1.5.2](../docs/DEVPLAN.md#feature-152-browser-automation-testing-infrastructure)
- [Testing Guidelines](../AGENTS.md#testing)
