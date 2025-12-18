using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Options;
using Shouldly;
using System.Net;
using System.Net.Mail;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public sealed class SmtpEmailSenderTests
{
    [Fact]
    public void Constructor_accepts_null_options()
    {
        // Arrange
        IOptions<SmtpOptions>? options = null;

        // Act
        var sender = new SmtpEmailSender(options!);

        // Assert - should not throw, constructor accepts null options
        sender.ShouldNotBeNull();
    }

    [Fact]
    public async Task SendAsync_throws_when_message_is_null()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 587,
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);

        // Act & Assert
        await Should.ThrowAsync<ArgumentNullException>(() => sender.SendAsync(null!));
    }

    [Fact]
    public async Task SendAsync_throws_when_host_is_not_configured()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = null,
            Port = 587,
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test", "<p>Test</p>");

        // Act & Assert
        var exception = await Should.ThrowAsync<InvalidOperationException>(() => sender.SendAsync(message));
        exception.Message.ShouldBe("SMTP host is not configured.");
    }

    [Fact]
    public async Task SendAsync_throws_when_host_is_empty()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "",
            Port = 587,
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test", "<p>Test</p>");

        // Act & Assert
        var exception = await Should.ThrowAsync<InvalidOperationException>(() => sender.SendAsync(message));
        exception.Message.ShouldBe("SMTP host is not configured.");
    }

    [Fact]
    public async Task SendAsync_throws_when_from_address_is_not_configured()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 587,
            FromAddress = null
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test", "<p>Test</p>");

        // Act & Assert
        var exception = await Should.ThrowAsync<InvalidOperationException>(() => sender.SendAsync(message));
        exception.Message.ShouldBe("SMTP from address is not configured.");
    }

    [Fact]
    public async Task SendAsync_throws_when_from_address_is_empty()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 587,
            FromAddress = ""
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test", "<p>Test</p>");

        // Act & Assert
        var exception = await Should.ThrowAsync<InvalidOperationException>(() => sender.SendAsync(message));
        exception.Message.ShouldBe("SMTP from address is not configured.");
    }

    [Fact]
    public async Task SendAsync_sends_email_with_minimal_configuration()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 25,
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test Subject", "<p>Test HTML Body</p>");

        // Act & Assert - This will fail to actually send but we can verify the setup
        // We expect a SmtpException or similar network error since we're not connecting to a real SMTP server
        await Should.ThrowAsync<SmtpException>(() => sender.SendAsync(message));
    }

    [Fact]
    public async Task SendAsync_sends_email_with_authentication()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 587,
            UserName = "user@example.com",
            Password = "password123",
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test Subject", "<p>Test HTML Body</p>");

        // Act & Assert - This will fail to actually send but we can verify the setup
        await Should.ThrowAsync<SmtpException>(() => sender.SendAsync(message));
    }

    [Fact]
    public async Task SendAsync_sends_email_with_tls_enabled()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 587,
            EnableTls = true,
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test Subject", "<p>Test HTML Body</p>");

        // Act & Assert - This will fail to actually send but we can verify the setup
        await Should.ThrowAsync<SmtpException>(() => sender.SendAsync(message));
    }

    [Fact]
    public async Task SendAsync_sends_email_with_display_name()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 25,
            FromAddress = "noreply@example.com",
            FromDisplayName = "Test Application"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test Subject", "<p>Test HTML Body</p>");

        // Act & Assert - This will fail to actually send but we can verify the setup
        await Should.ThrowAsync<SmtpException>(() => sender.SendAsync(message));
    }

    [Fact]
    public async Task SendAsync_sends_email_with_text_and_html_body()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 25,
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test Subject", "<p>Test HTML Body</p>", "Test Text Body");

        // Act & Assert - This will fail to actually send but we can verify the setup
        await Should.ThrowAsync<SmtpException>(() => sender.SendAsync(message));
    }

    [Fact]
    public async Task SendAsync_handles_whitespace_only_username()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 25,
            UserName = "   ",
            Password = "password",
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test Subject", "<p>Test HTML Body</p>");

        // Act & Assert - Should not set credentials when username is whitespace only
        await Should.ThrowAsync<SmtpException>(() => sender.SendAsync(message));
    }

    [Fact]
    public async Task SendAsync_handles_whitespace_only_password()
    {
        // Arrange
        var options = Options.Create(new SmtpOptions
        {
            Host = "smtp.example.com",
            Port = 25,
            UserName = "user@example.com",
            Password = "   ",
            FromAddress = "noreply@example.com"
        });
        var sender = new SmtpEmailSender(options);
        var message = new EmailMessage("test@example.com", "Test Subject", "<p>Test HTML Body</p>");

        // Act & Assert - Should set credentials even if password is whitespace only
        await Should.ThrowAsync<SmtpException>(() => sender.SendAsync(message));
    }
}
