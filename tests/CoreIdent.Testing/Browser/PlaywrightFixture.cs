using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace CoreIdent.Testing.Browser;

/// <summary>
/// Playwright fixture for browser automation testing.
/// Provides deterministic tracing and screenshot capture on failure.
/// </summary>
public class PlaywrightFixture : IAsyncDisposable
{
    private IPlaywright? _playwright;
    public IBrowser Browser { get; private set; } = null!;

    public async ValueTask InitializeAsync()
    {
        _playwright = await Playwright.CreateAsync();

        Browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true
        });
    }

    public async ValueTask DisposeAsync()
    {
        await Browser.CloseAsync();
        _playwright?.Dispose();
    }

    /// <summary>
    /// Creates a new browser context with tracing enabled.
    /// </summary>
    public async Task<IBrowserContext> CreateContextAsync(
        string traceName,
        bool captureScreenshots = true,
        bool captureTraces = true)
    {
        var context = await Browser.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true
        });

        if (captureTraces)
        {
            await context.Tracing.StartAsync(new TracingStartOptions
            {
                Name = traceName,
                Screenshots = captureScreenshots,
                Snapshots = true,
                Sources = true
            });
        }

        return context;
    }
}

/// <summary>
/// Base class for Playwright-based tests with automatic cleanup and diagnostics.
/// Use with xUnit's dependency injection: public MyTest(PlaywrightFixture fixture) => _fixture = fixture;
/// </summary>
public abstract class PlaywrightTestBase : IAsyncDisposable
{
    protected PlaywrightFixture Fixture { get; }
    protected IBrowserContext Context { get; private set; } = null!;
    protected IPage Page { get; private set; } = null!;
    private bool _initialized;

    protected PlaywrightTestBase(PlaywrightFixture fixture)
    {
        Fixture = fixture;
    }

    public async ValueTask InitializeAsync()
    {
        if (_initialized) return;
        _initialized = true;

        Context = await Fixture.CreateContextAsync(
            GetType().Name,
            captureScreenshots: true,
            captureTraces: true);

        Page = await Context.NewPageAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (Context != null!)
        {
            await Context.Tracing.StopAsync();
        }

        if (Page != null!)
        {
            await Page.CloseAsync();
        }

        if (Context != null!)
        {
            await Context.CloseAsync();
        }
    }

    /// <summary>
    /// Navigates to a URL and waits for the page to load.
    /// </summary>
    protected async Task GoToAsync(string url)
    {
        await Page.GotoAsync(url);
    }

    /// <summary>
    /// Fills a form input by selector.
    /// </summary>
    protected async Task FillAsync(string selector, string value)
    {
        await Page.FillAsync(selector, value);
    }

    /// <summary>
    /// Clicks an element by selector.
    /// </summary>
    protected async Task ClickAsync(string selector)
    {
        await Page.ClickAsync(selector);
    }

    /// <summary>
    /// Gets the current page URL.
    /// </summary>
    protected string Url() => Page.Url;

    /// <summary>
    /// Waits for a selector to be visible.
    /// </summary>
    protected async Task<IElementHandle> WaitForSelectorAsync(string selector)
    {
        return await Page.WaitForSelectorAsync(selector)
               ?? throw new PlaywrightException($"Selector '{selector}' not found");
    }

    /// <summary>
    /// Checks if an element exists.
    /// </summary>
    protected async Task<bool> IsVisibleAsync(string selector)
    {
        return await Page.IsVisibleAsync(selector);
    }

    /// <summary>
    /// Gets text content from an element.
    /// </summary>
    protected async Task<string?> TextContentAsync(string selector)
    {
        return await Page.TextContentAsync(selector);
    }

    /// <summary>
    /// Evaluates JavaScript on the page.
    /// </summary>
    protected async Task<T> EvaluateAsync<T>(string script, object? args = null)
    {
        return await Page.EvaluateAsync<T>(script, args);
    }
}
