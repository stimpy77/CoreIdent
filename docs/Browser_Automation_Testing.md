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

## Supported CI Runners and Platform Requirements

### CI Runner Support Matrix

| Runner Type | Unit Tests | Integration Tests | Browser E2E | MAUI UI | WPF UI |
|-------------|:----------:|:-----------------:|:-----------:|:-------:|:------:|
| **GitHub Actions** |
| `ubuntu-latest` | ✅ | ✅ | ✅ | ⚠️¹ | ❌ |
| `windows-latest` | ✅ | ✅ | ✅ | ⚠️¹ | ✅² |
| `macos-latest` | ✅ | ✅ | ✅ | ⚠️¹ | ❌ |
| **Azure DevOps** |
| `ubuntu-latest` | ✅ | ✅ | ✅ | ⚠️¹ | ❌ |
| `windows-latest` | ✅ | ✅ | ✅ | ⚠️¹ | ✅² |
| `vmImage: macOS-latest` | ✅ | ✅ | ✅ | ⚠️¹ | ❌ |
| **Self-Hosted** |
| Linux | ✅ | ✅ | ✅ | ⚠️³ | ❌ |
| Windows | ✅ | ✅ | ✅ | ⚠️³ | ✅ |
| macOS | ✅ | ✅ | ✅ | ⚠️³ | ❌ |

**Notes:**
- ✅ = Fully supported
- ⚠️ = Partial support with additional setup
- ❌ = Not supported
- ¹ = Android emulator tests possible but slow; iOS requires macOS with Xcode
- ² = Requires Windows UI (non-headless agent)
- ³ = Requires platform-specific emulators/simulators installed

### Platform Requirements by Test Type

#### Playwright Browser Tests (Current - Recommended)

**Minimum Requirements:**
- .NET 10 SDK
- Playwright browsers: `dotnet playwright install --with-deps chromium`
- 2GB RAM minimum, 4GB recommended
- No display required (runs headless)

**GitHub Actions Setup:**
```yaml
- name: Install Playwright
  run: dotnet playwright install --with-deps chromium
```

#### MAUI UI Automation (Future - Feature 1.5.3)

> **Status:** Not yet implemented. Requirements documented for planning purposes.

**Android Testing:**
| Requirement | CI Runner | Notes |
|-------------|-----------|-------|
| Android SDK | All | Auto-installed via `setup-android` action |
| Android Emulator | All | Requires hardware acceleration (KVM on Linux) |
| Java 17+ | All | Required by Android SDK |

```yaml
# GitHub Actions example for MAUI Android
jobs:
  maui-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-java@v4
        with:
          java-version: 17
          distribution: temurin
      - name: Setup Android SDK
        uses: android-actions/setup-android@v3
      - name: Start Emulator
        run: |
          $ANDROID_HOME/emulator/emulator -avd test -no-window -gpu swiftshader &
          adb wait-for-device
```

**iOS Testing:**
| Requirement | CI Runner | Notes |
|-------------|-----------|-------|
| macOS runner | macOS only | iOS simulator requires macOS |
| Xcode 15+ | macOS only | Required for iOS development |
| iOS Simulator | macOS only | Auto-available on macOS runners |

```yaml
# GitHub Actions example for MAUI iOS
jobs:
  maui-ios:
    runs-on: macos-latest
    steps:
      - name: Select Xcode
        run: sudo xcode-select -s /Applications/Xcode_15.4.app
      - name: Boot iOS Simulator
        run: |
          xcrun simctl boot "iPhone 15 Pro"
```

**Cross-Platform MAUI CI Strategy:**
```yaml
jobs:
  maui-unit-tests:
    runs-on: ubuntu-latest  # No platform-specific dependencies

  maui-android-e2e:
    runs-on: ubuntu-latest  # Android emulator with KVM
    if: github.event.schedule  # Nightly only (slow)

  maui-ios-e2e:
    runs-on: macos-latest  # iOS simulator required
    if: github.event.schedule  # Nightly only (slow)
```

#### WPF UI Automation (Future - Feature 1.5.4)

> **Status:** Not yet implemented. Requirements documented for planning purposes.

**Requirements:**
| Requirement | CI Runner | Notes |
|-------------|-----------|-------|
| Windows runner | Windows only | WPF is Windows-only |
| Non-headless agent | Self-hosted or Windows UI | UI automation needs display |
| .NET 10 Windows workload | Windows | `net10.0-windows` TFM |

**CI Considerations:**
- GitHub Actions `windows-latest` does NOT support UI automation by default
- Options for WPF UI testing:
  1. **Self-hosted Windows runner** with display access
  2. **FlaUI + Microsoft UI Automation** (can work headless in some scenarios)
  3. **Virtual display** using third-party tools (not officially supported)

```yaml
# Self-hosted Windows runner with UI access
jobs:
  wpf-ui-tests:
    runs-on: [self-hosted, windows, ui-enabled]
    steps:
      - name: Run WPF UI Tests
        run: dotnet test CoreIdent.Client.Wpf.Tests --filter "Category=UI"
```

**Alternative: Unit + Integration Tests Only**

For WPF clients without UI automation:
```yaml
jobs:
  wpf-headless-tests:
    runs-on: windows-latest
    steps:
      - name: Run WPF Unit + Integration Tests
        run: dotnet test CoreIdent.Client.Wpf.Tests --filter "Category!=UI"
```

### Cost and Time Considerations

| Test Type | Typical Duration | CI Minutes | Recommendation |
|-----------|------------------|------------|----------------|
| Unit Tests | 10-30s | ~0.5 min | Every PR |
| Integration Tests | 30-60s | ~1 min | Every PR |
| Browser E2E (Playwright) | 1-5 min | ~3 min | Every PR |
| Android Emulator E2E | 10-20 min | ~15 min | Nightly/Release |
| iOS Simulator E2E | 10-20 min | ~15 min | Nightly/Release |
| WPF UI E2E | 5-10 min | ~8 min | Nightly/Release |

### Recommended CI Strategy

```yaml
# PR builds: Fast feedback
on: pull_request
jobs:
  quick-tests:  # < 5 minutes
    runs-on: ubuntu-latest
    steps:
      - run: dotnet test --filter "Category!=E2E&Category!=UI"

# Main branch: Full E2E
on:
  push:
    branches: [main]
jobs:
  browser-e2e:
    runs-on: ubuntu-latest
    steps:
      - run: dotnet playwright install --with-deps chromium
      - run: dotnet test --filter "Category=E2E"

# Nightly: Platform-specific UI tests
on:
  schedule:
    - cron: '0 2 * * *'
jobs:
  android-e2e:
    runs-on: ubuntu-latest
    # ... Android emulator setup
  ios-e2e:
    runs-on: macos-latest
    # ... iOS simulator setup
  wpf-e2e:
    runs-on: [self-hosted, windows, ui-enabled]
    # ... WPF UI automation
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
