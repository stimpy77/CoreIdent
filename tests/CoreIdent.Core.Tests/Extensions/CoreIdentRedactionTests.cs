using CoreIdent.Core.Extensions;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Extensions;

public class CoreIdentRedactionTests
{
    [Fact]
    public void MaskEmail_returns_empty_for_null_or_whitespace()
    {
        CoreIdentRedaction.MaskEmail(null).ShouldBe(string.Empty, "Null email should return empty string.");
        CoreIdentRedaction.MaskEmail("").ShouldBe(string.Empty, "Empty email should return empty string.");
        CoreIdentRedaction.MaskEmail("   ").ShouldBe(string.Empty, "Whitespace email should return empty string.");
    }

    [Fact]
    public void MaskEmail_masks_invalid_addresses_with_generic_mask()
    {
        CoreIdentRedaction.MaskEmail("abc").ShouldBe("a*c", "Non-email input should be masked generically.");
        CoreIdentRedaction.MaskEmail("a@").ShouldBe("**", "Invalid email missing domain should be masked generically.");
        CoreIdentRedaction.MaskEmail("@b").ShouldBe("**", "Invalid email missing local part should be masked generically.");
    }

    [Fact]
    public void MaskEmail_masks_local_and_domain_components()
    {
        CoreIdentRedaction.MaskEmail("a@b.com").ShouldBe("*@*.com", "Single-character local/domain should be masked with '*'.");
        CoreIdentRedaction.MaskEmail("ab@cd.com").ShouldBe("a*@c*.com", "Two-character local/domain should retain first char only.");
        CoreIdentRedaction.MaskEmail("alice@example.com").ShouldBe("a***e@e*****e.com", "Longer local/domain should retain first and last chars only.");
    }

    [Fact]
    public void MaskEmail_masks_domain_without_tld_using_generic_mask()
    {
        CoreIdentRedaction.MaskEmail("a@localhost").ShouldBe("*@l*******t", "Domain without dot should be masked generically.");
    }

    [Fact]
    public void MaskPhone_returns_empty_for_null_or_whitespace()
    {
        CoreIdentRedaction.MaskPhone(null).ShouldBe(string.Empty, "Null phone should return empty string.");
        CoreIdentRedaction.MaskPhone("").ShouldBe(string.Empty, "Empty phone should return empty string.");
        CoreIdentRedaction.MaskPhone("  ").ShouldBe(string.Empty, "Whitespace phone should return empty string.");
    }

    [Fact]
    public void MaskPhone_masks_short_numbers_with_only_stars()
    {
        CoreIdentRedaction.MaskPhone("12").ShouldBe("**", "Phone numbers with <=4 digits should be fully masked.");
        CoreIdentRedaction.MaskPhone("1234").ShouldBe("****", "Phone numbers with exactly 4 digits should be fully masked.");
    }

    [Fact]
    public void MaskPhone_returns_last4_for_long_numbers()
    {
        CoreIdentRedaction.MaskPhone("+1 (555) 123-4567").ShouldBe("***4567", "Phone mask should return *** followed by last 4 digits.");
    }
}
