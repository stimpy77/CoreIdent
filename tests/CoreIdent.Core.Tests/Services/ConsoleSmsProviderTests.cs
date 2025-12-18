using CoreIdent.Core.Services;
using Shouldly;
using System.Collections.Concurrent;
using System;
using System.IO;
using System.Threading;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public sealed class ConsoleSmsProviderTests
{
    private static (ConsoleSmsProvider Provider, CapturingLoggerProvider LoggerProvider) CreateProvider()
    {
        var loggerProvider = new CapturingLoggerProvider();
        var loggerFactory = LoggerFactory.Create(builder => builder.AddProvider(loggerProvider));
        var logger = loggerFactory.CreateLogger<ConsoleSmsProvider>();
        return (new ConsoleSmsProvider(logger), loggerProvider);
    }

    [Fact]
    public async Task SendAsync_writes_message_to_console()
    {
        // Arrange
        var (provider, loggerProvider) = CreateProvider();
        var phoneNumber = "+1234567890";
        var message = "Test SMS message";
        
        // Capture console output
        var originalOut = Console.Out;
        using var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        // Act
        await provider.SendAsync(phoneNumber, message);

        // Restore console output
        Console.SetOut(originalOut);

        // Assert
        var output = stringWriter.ToString();
        output.ShouldNotContain("[CoreIdent SMS]", Shouldly.Case.Sensitive, "ConsoleSmsProvider should not write SMS content to stdout.");

        var log = loggerProvider.Messages.LastOrDefault() ?? string.Empty;
        log.ShouldContain("[CoreIdent SMS] Sending SMS to", Shouldly.Case.Sensitive, "Provider should log an SMS send event.");
        log.ShouldContain("***7890", Shouldly.Case.Sensitive, "Provider should log masked phone number.");
        log.ShouldNotContain(message, Shouldly.Case.Sensitive, "Provider must not log SMS message body.");
    }

    [Fact]
    public async Task SendAsync_handles_empty_phone_number()
    {
        // Arrange
        var (provider, loggerProvider) = CreateProvider();
        var phoneNumber = "";
        var message = "Test message";
        
        // Capture console output
        var originalOut = Console.Out;
        using var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        // Act
        await provider.SendAsync(phoneNumber, message);

        // Restore console output
        Console.SetOut(originalOut);

        // Assert
        var output = stringWriter.ToString();
        output.ShouldNotContain("[CoreIdent SMS]", Shouldly.Case.Sensitive, "ConsoleSmsProvider should not write SMS content to stdout.");

        var log = loggerProvider.Messages.LastOrDefault() ?? string.Empty;
        log.ShouldContain("[CoreIdent SMS] Sending SMS to", Shouldly.Case.Sensitive, "Provider should log an SMS send event.");
        log.ShouldNotContain(message, Shouldly.Case.Sensitive, "Provider must not log SMS message body.");
    }

    [Fact]
    public async Task SendAsync_handles_empty_message()
    {
        // Arrange
        var (provider, loggerProvider) = CreateProvider();
        var phoneNumber = "+1234567890";
        var message = "";
        
        // Capture console output
        var originalOut = Console.Out;
        using var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        // Act
        await provider.SendAsync(phoneNumber, message);

        // Restore console output
        Console.SetOut(originalOut);

        // Assert
        var output = stringWriter.ToString();
        output.ShouldNotContain("[CoreIdent SMS]", Shouldly.Case.Sensitive, "ConsoleSmsProvider should not write SMS content to stdout.");

        var log = loggerProvider.Messages.LastOrDefault() ?? string.Empty;
        log.ShouldContain("[CoreIdent SMS] Sending SMS to", Shouldly.Case.Sensitive, "Provider should log an SMS send event.");
        log.ShouldContain("***7890", Shouldly.Case.Sensitive, "Provider should log masked phone number.");
    }

    [Fact]
    public async Task SendAsync_handles_null_message()
    {
        // Arrange
        var (provider, loggerProvider) = CreateProvider();
        var phoneNumber = "+1234567890";
        string? message = null;
        
        // Capture console output
        var originalOut = Console.Out;
        using var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        // Act
        await provider.SendAsync(phoneNumber, message!);

        // Restore console output
        Console.SetOut(originalOut);

        // Assert
        var output = stringWriter.ToString();
        output.ShouldNotContain("[CoreIdent SMS]", Shouldly.Case.Sensitive, "ConsoleSmsProvider should not write SMS content to stdout.");

        var log = loggerProvider.Messages.LastOrDefault() ?? string.Empty;
        log.ShouldContain("[CoreIdent SMS] Sending SMS to", Shouldly.Case.Sensitive, "Provider should log an SMS send event.");
        log.ShouldContain("***7890", Shouldly.Case.Sensitive, "Provider should log masked phone number.");
    }

    [Fact]
    public async Task SendAsync_handles_special_characters()
    {
        // Arrange
        var (provider, loggerProvider) = CreateProvider();
        var phoneNumber = "+1(234) 567-890";
        var message = "Test message with special chars: !@#$%^&*()";
        
        // Capture console output
        var originalOut = Console.Out;
        using var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        // Act
        await provider.SendAsync(phoneNumber, message);

        // Restore console output
        Console.SetOut(originalOut);

        // Assert
        var output = stringWriter.ToString();
        output.ShouldNotContain("[CoreIdent SMS]", Shouldly.Case.Sensitive, "ConsoleSmsProvider should not write SMS content to stdout.");

        var log = loggerProvider.Messages.LastOrDefault() ?? string.Empty;
        log.ShouldContain("[CoreIdent SMS] Sending SMS to", Shouldly.Case.Sensitive, "Provider should log an SMS send event.");
        log.ShouldContain("***7890", Shouldly.Case.Sensitive, "Provider should log masked phone number based on digits.");
        log.ShouldNotContain(message, Shouldly.Case.Sensitive, "Provider must not log SMS message body.");
    }

    [Fact]
    public async Task SendAsync_respects_cancellation_token()
    {
        // Arrange
        var (provider, loggerProvider) = CreateProvider();
        var phoneNumber = "+1234567890";
        var message = "Test message";
        var cts = new CancellationTokenSource();
        
        // Capture console output
        var originalOut = Console.Out;
        using var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        // Act
        await provider.SendAsync(phoneNumber, message, cts.Token);

        // Restore console output
        Console.SetOut(originalOut);

        // Assert
        var output = stringWriter.ToString();
        output.ShouldNotContain("[CoreIdent SMS]", Shouldly.Case.Sensitive, "ConsoleSmsProvider should not write SMS content to stdout.");

        var log = loggerProvider.Messages.LastOrDefault() ?? string.Empty;
        log.ShouldContain("[CoreIdent SMS] Sending SMS to", Shouldly.Case.Sensitive, "Provider should log an SMS send event.");
        log.ShouldContain("***7890", Shouldly.Case.Sensitive, "Provider should log masked phone number.");
        log.ShouldNotContain(message, Shouldly.Case.Sensitive, "Provider must not log SMS message body.");
    }

    [Fact]
    public async Task SendAsync_handles_cancelled_token()
    {
        // Arrange
        var (provider, loggerProvider) = CreateProvider();
        var phoneNumber = "+1234567890";
        var message = "Test message";
        var cts = new CancellationTokenSource();
        cts.Cancel();
        
        // Capture console output
        var originalOut = Console.Out;
        using var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        // Act
        await provider.SendAsync(phoneNumber, message, cts.Token);

        // Restore console output
        Console.SetOut(originalOut);

        // Assert
        var output = stringWriter.ToString();
        output.ShouldNotContain("[CoreIdent SMS]", Shouldly.Case.Sensitive, "ConsoleSmsProvider should not write SMS content to stdout.");

        var log = loggerProvider.Messages.LastOrDefault() ?? string.Empty;
        log.ShouldContain("[CoreIdent SMS] Sending SMS to", Shouldly.Case.Sensitive, "Provider should log an SMS send event.");
        log.ShouldContain("***7890", Shouldly.Case.Sensitive, "Provider should log masked phone number.");
        log.ShouldNotContain(message, Shouldly.Case.Sensitive, "Provider must not log SMS message body.");
    }

    [Fact]
    public async Task SendAsync_returns_completed_task()
    {
        // Arrange
        var (provider, _) = CreateProvider();
        var phoneNumber = "+1234567890";
        var message = "Test message";

        // Act
        var task = provider.SendAsync(phoneNumber, message);

        // Assert
        task.IsCompleted.ShouldBeTrue();
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages.ToArray();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(_messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue(formatter(state, exception));
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new();

                public void Dispose()
                {
                }
            }
        }
    }
}
