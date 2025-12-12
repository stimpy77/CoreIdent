using System.Security.Claims;
using CoreIdent.Core.Extensions;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public class ClaimsPrincipalExtensionsTests
{
    [Fact]
    public void Email_returns_email_claims()
    {
        var principal = CreatePrincipal(("email", "user@example.com"));
        principal.Email.ShouldBe("user@example.com", "Email should prefer standard or lowercase email claim types.");
    }

    [Fact]
    public void UserId_prefers_nameidentifier_then_sub()
    {
        var principal = CreatePrincipal((ClaimTypes.NameIdentifier, "123"), ("sub", "abc"));
        principal.UserId.ShouldBe("123", "NameIdentifier should take precedence over sub.");

        var principalSubOnly = CreatePrincipal(("sub", "abc"));
        principalSubOnly.UserId.ShouldBe("abc", "Falls back to sub when NameIdentifier is absent.");
    }

    [Fact]
    public void GetUserIdAsGuid_parses_guid_or_throws()
    {
        var guid = Guid.NewGuid();
        var principal = CreatePrincipal((ClaimTypes.NameIdentifier, guid.ToString()));
        principal.GetUserIdAsGuid().ShouldBe(guid, "Should parse valid GUID user id.");

        var bad = CreatePrincipal((ClaimTypes.NameIdentifier, "not-a-guid"));
        Should.Throw<InvalidOperationException>(() => bad.GetUserIdAsGuid(), "Invalid GUID should throw.");
    }

    [Fact]
    public void GetClaim_parses_value_or_returns_default()
    {
        var principal = CreatePrincipal(("age", "42"));
        principal.GetClaim<int>("age").ShouldBe(42, "Should parse typed claim.");
        var missing = principal.GetClaim<int>("missing");
        missing.ShouldBe(0, "Missing claim should return default (0 for int).");
    }

    [Fact]
    public void GetClaim_throws_when_parse_fails()
    {
        var principal = CreatePrincipal(("age", "not-an-int"));
        Should.Throw<InvalidOperationException>(() => principal.GetClaim<int>("age"), "Unparsable claim should throw.");
    }

    [Fact]
    public void GetRoles_returns_role_claims()
    {
        var principal = CreatePrincipal((ClaimTypes.Role, "admin"), ("role", "user"));
        principal.GetRoles().ShouldBe(new[] { "admin", "user" }, "Should aggregate role claim types.");
    }

    [Fact]
    public void IsInRole_with_comparison_ignores_case()
    {
        var principal = CreatePrincipal((ClaimTypes.Role, "Admin"));
        principal.IsInRole("admin", StringComparison.OrdinalIgnoreCase).ShouldBeTrue("Should match role ignoring case.");
        principal.IsInRole("user", StringComparison.OrdinalIgnoreCase).ShouldBeFalse("Should not match absent role.");
    }

    [Fact]
    public void IsInRole_with_ordinal_is_case_sensitive()
    {
        var principal = CreatePrincipal((ClaimTypes.Role, "Admin"));
        principal.IsInRole("Admin", StringComparison.Ordinal).ShouldBeTrue("Should match role with exact case.");
        principal.IsInRole("admin", StringComparison.Ordinal).ShouldBeFalse("Should not match role with different case when using Ordinal.");
    }

    private static ClaimsPrincipal CreatePrincipal(params (string type, string value)[] claims)
    {
        var identity = new ClaimsIdentity(
            claims.Select(c => new Claim(c.type, c.value)),
            authenticationType: "TestAuth",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role);
        return new ClaimsPrincipal(identity);
    }
}
