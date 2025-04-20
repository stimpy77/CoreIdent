using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace CoreIdent.Integration.Tests;

public class XUnitLoggerProvider : ILoggerProvider
{
    private readonly Xunit.Abstractions.ITestOutputHelper _output;
    private readonly ConcurrentDictionary<string, XUnitLogger> _loggers = new();

    public XUnitLoggerProvider(Xunit.Abstractions.ITestOutputHelper output)
    {
        _output = output;
    }

    public ILogger CreateLogger(string categoryName)
    {
        return _loggers.GetOrAdd(categoryName, name => new XUnitLogger(_output, name));
    }

    public void Dispose()
    {
        _loggers.Clear();
        GC.SuppressFinalize(this);
    }
}
