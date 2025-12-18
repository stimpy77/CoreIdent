using CoreIdent.Core.Services;
using Shouldly;
using System;
using System.IO;
using System.Threading;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public sealed class ConsoleSmsProviderTests
{
    [Fact]
    public async Task SendAsync_writes_message_to_console()
    {
        // Arrange
        var provider = new ConsoleSmsProvider();
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
        output.ShouldContain("[CoreIdent SMS]");
        output.ShouldContain($"To={phoneNumber}");
        output.ShouldContain($"Message={message}");
    }

    [Fact]
    public async Task SendAsync_handles_empty_phone_number()
    {
        // Arrange
        var provider = new ConsoleSmsProvider();
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
        output.ShouldContain("[CoreIdent SMS]");
        output.ShouldContain("To=");
        output.ShouldContain($"Message={message}");
    }

    [Fact]
    public async Task SendAsync_handles_empty_message()
    {
        // Arrange
        var provider = new ConsoleSmsProvider();
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
        output.ShouldContain("[CoreIdent SMS]");
        output.ShouldContain($"To={phoneNumber}");
        output.ShouldContain("Message=");
    }

    [Fact]
    public async Task SendAsync_handles_null_message()
    {
        // Arrange
        var provider = new ConsoleSmsProvider();
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
        output.ShouldContain("[CoreIdent SMS]");
        output.ShouldContain($"To={phoneNumber}");
        output.ShouldContain("Message=");
    }

    [Fact]
    public async Task SendAsync_handles_special_characters()
    {
        // Arrange
        var provider = new ConsoleSmsProvider();
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
        output.ShouldContain("[CoreIdent SMS]");
        output.ShouldContain($"To={phoneNumber}");
        output.ShouldContain($"Message={message}");
    }

    [Fact]
    public async Task SendAsync_respects_cancellation_token()
    {
        // Arrange
        var provider = new ConsoleSmsProvider();
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
        output.ShouldContain("[CoreIdent SMS]");
        output.ShouldContain($"To={phoneNumber}");
        output.ShouldContain($"Message={message}");
    }

    [Fact]
    public async Task SendAsync_handles_cancelled_token()
    {
        // Arrange
        var provider = new ConsoleSmsProvider();
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
        output.ShouldContain("[CoreIdent SMS]");
        output.ShouldContain($"To={phoneNumber}");
        output.ShouldContain($"Message={message}");
    }

    [Fact]
    public async Task SendAsync_returns_completed_task()
    {
        // Arrange
        var provider = new ConsoleSmsProvider();
        var phoneNumber = "+1234567890";
        var message = "Test message";

        // Act
        var task = provider.SendAsync(phoneNumber, message);

        // Assert
        task.IsCompleted.ShouldBeTrue();
    }
}
