using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace CoreIdent.Integration.Tests;

public class XUnitLogger : ILogger
{
    private readonly Xunit.Abstractions.ITestOutputHelper _output;
    private readonly string _categoryName;

    public XUnitLogger(Xunit.Abstractions.ITestOutputHelper output, string categoryName)
    {
        _output = output;
        _categoryName = categoryName;
    }

    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NoopDisposable.Instance;

    public bool IsEnabled(LogLevel logLevel) => true; // Always enabled, filtering happens elsewhere

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        var message = formatter(state, exception);
        if (string.IsNullOrEmpty(message))
        {
            return;
        }

        var line = $"[{logLevel.ToString().ToUpperInvariant().Substring(0, 4)}] {_categoryName}: {message}";
        if (exception != null)
        {
            line += $"\nException: {exception}";
        }

        try
        {
            _output.WriteLine(line);
        }
        catch (InvalidOperationException) 
        { 
            // Ignore errors during test teardown where output might be disposed
        }
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static readonly NoopDisposable Instance = new();
        public void Dispose() { }
    }
}
