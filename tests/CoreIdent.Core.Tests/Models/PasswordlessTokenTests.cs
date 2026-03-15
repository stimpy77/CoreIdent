using CoreIdent.Core.Models;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Models;

public class PasswordlessTokenTests
{
    [Fact]
    public void Properties_default_to_expected_values()
    {
        var token = new PasswordlessToken();

        token.Id.ShouldBe(string.Empty, "Id should default to empty string.");
        token.Recipient.ShouldBe(string.Empty, "Recipient should default to empty string.");
        token.TokenType.ShouldBe(string.Empty, "TokenType should default to empty string.");
        token.TokenHash.ShouldBe(string.Empty, "TokenHash should default to empty string.");
        token.CreatedAt.ShouldBe(default(DateTime), "CreatedAt should default to default DateTime.");
        token.ExpiresAt.ShouldBe(default(DateTime), "ExpiresAt should default to default DateTime.");
        token.Consumed.ShouldBeFalse("Consumed should default to false.");
        token.UserId.ShouldBeNull("UserId should default to null.");
    }

    [Fact]
    public void Properties_round_trip_correctly()
    {
        var now = DateTime.UtcNow;
        var token = new PasswordlessToken
        {
            Id = "tok-1",
            Recipient = "user@example.com",
            TokenType = "email",
            TokenHash = "abc123",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(15),
            Consumed = true,
            UserId = "user-1"
        };

        token.Id.ShouldBe("tok-1", "Id should round-trip.");
        token.Recipient.ShouldBe("user@example.com", "Recipient should round-trip.");
        token.TokenType.ShouldBe("email", "TokenType should round-trip.");
        token.TokenHash.ShouldBe("abc123", "TokenHash should round-trip.");
        token.CreatedAt.ShouldBe(now, "CreatedAt should round-trip.");
        token.ExpiresAt.ShouldBe(now.AddMinutes(15), "ExpiresAt should round-trip.");
        token.Consumed.ShouldBeTrue("Consumed should round-trip.");
        token.UserId.ShouldBe("user-1", "UserId should round-trip.");
    }
}
