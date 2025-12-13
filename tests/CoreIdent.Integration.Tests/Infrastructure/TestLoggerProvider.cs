using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Integration.Tests.Infrastructure;

public sealed class TestLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    public IEnumerable<LogEntry> Entries => _entries.ToArray();

    public ILogger CreateLogger(string categoryName) => new TestLogger(categoryName, _entries);

    public void Dispose()
    {
    }

    private sealed class TestLogger(string categoryName, ConcurrentQueue<LogEntry> entries) : ILogger
    {
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            entries.Enqueue(new LogEntry(categoryName, logLevel, eventId, formatter(state, exception), exception));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }

    public sealed record LogEntry(string CategoryName, LogLevel Level, EventId EventId, string Message, Exception? Exception);
}
