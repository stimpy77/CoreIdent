using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Stores.InMemory;
using CoreIdent.Core.Tests.TestUtilities;
using Microsoft.Extensions.Options;
using Shouldly;

namespace CoreIdent.Core.Tests.Stores;

public sealed class InMemoryPasswordlessTokenStoreTests
{
    [Fact]
    public async Task CreateTokenAsync_GeneratesUniqueTokens()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        var options = Options.Create(new PasswordlessEmailOptions
        {
            MaxAttemptsPerHour = 10,
            TokenLifetime = TimeSpan.FromMinutes(15)
        });

        var smsOptions = Options.Create(new PasswordlessSmsOptions
        {
            MaxAttemptsPerHour = 10,
            OtpLifetime = TimeSpan.FromMinutes(5)
        });

        var store = new InMemoryPasswordlessTokenStore(time, options, smsOptions);

        var t1 = await store.CreateTokenAsync(new PasswordlessToken { Recipient = "user@example.com" });
        var t2 = await store.CreateTokenAsync(new PasswordlessToken { Recipient = "user@example.com" });

        t1.ShouldNotBeNullOrWhiteSpace();
        t2.ShouldNotBeNullOrWhiteSpace();
        t1.ShouldNotBe(t2, "tokens should be unique");
    }

    [Fact]
    public async Task ValidateAndConsumeAsync_ReturnsHashedToken_AndHashIsConsistent()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        var options = Options.Create(new PasswordlessEmailOptions
        {
            MaxAttemptsPerHour = 10,
            TokenLifetime = TimeSpan.FromMinutes(15)
        });

        var smsOptions = Options.Create(new PasswordlessSmsOptions
        {
            MaxAttemptsPerHour = 10,
            OtpLifetime = TimeSpan.FromMinutes(5)
        });

        var store = new InMemoryPasswordlessTokenStore(time, options, smsOptions);

        var raw = await store.CreateTokenAsync(new PasswordlessToken { Recipient = "user@example.com" });
        var consumed = await store.ValidateAndConsumeAsync(raw);

        consumed.ShouldNotBeNull();
        consumed!.TokenHash.ShouldNotBeNullOrWhiteSpace();
        consumed.TokenHash.ShouldNotBe(raw, "stored token hash must not equal the raw token");

        var expected = ComputeSha256HexLower(raw);
        consumed.TokenHash.ShouldBe(expected, "token hashing should be consistent and deterministic");
    }

    [Fact]
    public async Task CreateTokenAsync_Throws_WhenRateLimitExceeded()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        var options = Options.Create(new PasswordlessEmailOptions
        {
            MaxAttemptsPerHour = 1,
            TokenLifetime = TimeSpan.FromMinutes(15)
        });

        var smsOptions = Options.Create(new PasswordlessSmsOptions
        {
            MaxAttemptsPerHour = 10,
            OtpLifetime = TimeSpan.FromMinutes(5)
        });

        var store = new InMemoryPasswordlessTokenStore(time, options, smsOptions);

        await store.CreateTokenAsync(new PasswordlessToken { Recipient = "user@example.com" });

        await Should.ThrowAsync<PasswordlessRateLimitExceededException>(
            () => store.CreateTokenAsync(new PasswordlessToken { Recipient = "user@example.com" }),
            "second token within the hour should exceed rate limit");

        // advancing out of the 1 hour window should allow another token
        time.Advance(TimeSpan.FromHours(1).Add(TimeSpan.FromSeconds(1)));

        await Should.NotThrowAsync(
            () => store.CreateTokenAsync(new PasswordlessToken { Recipient = "user@example.com" }),
            "rate limit window should reset after an hour");
    }

    [Fact]
    public async Task ValidateAndConsumeAsync_ReturnsNull_ForExpiredToken()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        var options = Options.Create(new PasswordlessEmailOptions
        {
            MaxAttemptsPerHour = 10,
            TokenLifetime = TimeSpan.FromMinutes(10)
        });

        var smsOptions = Options.Create(new PasswordlessSmsOptions
        {
            MaxAttemptsPerHour = 10,
            OtpLifetime = TimeSpan.FromMinutes(5)
        });

        var store = new InMemoryPasswordlessTokenStore(time, options, smsOptions);

        var raw = await store.CreateTokenAsync(new PasswordlessToken { Recipient = "user@example.com" });

        time.Advance(TimeSpan.FromMinutes(11));

        (await store.ValidateAndConsumeAsync(raw)).ShouldBeNull("expired token should not validate");
    }

    [Fact]
    public async Task ValidateAndConsumeAsync_ConsumesToken_AndIsSingleUse()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        var options = Options.Create(new PasswordlessEmailOptions
        {
            MaxAttemptsPerHour = 10,
            TokenLifetime = TimeSpan.FromMinutes(15)
        });

        var smsOptions = Options.Create(new PasswordlessSmsOptions
        {
            MaxAttemptsPerHour = 10,
            OtpLifetime = TimeSpan.FromMinutes(5)
        });

        var store = new InMemoryPasswordlessTokenStore(time, options, smsOptions);

        var raw = await store.CreateTokenAsync(new PasswordlessToken { Recipient = "user@example.com" });

        var first = await store.ValidateAndConsumeAsync(raw);
        first.ShouldNotBeNull("first validation should succeed");
        first!.Recipient.ShouldBe("user@example.com");
        first.Consumed.ShouldBeTrue("token should be marked consumed after validation");

        (await store.ValidateAndConsumeAsync(raw)).ShouldBeNull("token should be single use");
    }

    [Fact]
    public async Task CreateTokenAsync_ForSmsOtp_GeneratesSixDigitNumericOtp()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        var emailOptions = Options.Create(new PasswordlessEmailOptions
        {
            MaxAttemptsPerHour = 10,
            TokenLifetime = TimeSpan.FromMinutes(15)
        });

        var smsOptions = Options.Create(new PasswordlessSmsOptions
        {
            MaxAttemptsPerHour = 10,
            OtpLifetime = TimeSpan.FromMinutes(5)
        });

        var store = new InMemoryPasswordlessTokenStore(time, emailOptions, smsOptions);

        var otp = await store.CreateTokenAsync(new PasswordlessToken
        {
            Recipient = "+15551234567",
            TokenType = PasswordlessTokenTypes.SmsOtp
        });

        otp.Length.ShouldBe(6, "otp should be 6 digits");
        otp.All(char.IsDigit).ShouldBeTrue("otp should be numeric");
    }

    [Fact]
    public async Task ValidateAndConsumeAsync_burns_token_after_max_failed_attempts()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2025, 12, 12, 0, 0, 0, TimeSpan.Zero));

        var emailOptions = Options.Create(new PasswordlessEmailOptions
        {
            MaxAttemptsPerHour = 100,
            TokenLifetime = TimeSpan.FromMinutes(15)
        });

        var smsOptions = Options.Create(new PasswordlessSmsOptions
        {
            MaxAttemptsPerHour = 100,
            OtpLifetime = TimeSpan.FromMinutes(5),
            MaxVerifyAttempts = 3
        });

        var store = new InMemoryPasswordlessTokenStore(time, emailOptions, smsOptions);

        var otp = await store.CreateTokenAsync(new PasswordlessToken
        {
            Recipient = "+15551234567",
            TokenType = PasswordlessTokenTypes.SmsOtp
        });

        // Submit wrong OTPs — 3 failures should burn the real token
        for (var i = 0; i < 3; i++)
        {
            var result = await store.ValidateAndConsumeAsync("000000", PasswordlessTokenTypes.SmsOtp, "+15551234567");
            result.ShouldBeNull($"Wrong OTP attempt {i + 1} should return null.");
        }

        // Now submit the correct OTP — should fail because the token was burned
        var final = await store.ValidateAndConsumeAsync(otp, PasswordlessTokenTypes.SmsOtp, "+15551234567");
        final.ShouldBeNull("Correct OTP should fail after max failed attempts because the token was burned.");
    }

    private static string ComputeSha256HexLower(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
