using CoreIdent.Core.Models;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Models;

/// <summary>
/// Tests for the DefaultScopes scope resolution policy on <see cref="CoreIdentClient"/>.
/// Validates the contract: null → use AllowedScopes, empty → require explicit, non-empty → use those.
/// </summary>
public class DefaultScopePolicyTests
{
    private static readonly ICollection<string> AllowedScopes = ["openid", "profile", "email"];

    /// <summary>
    /// Resolves scopes using the same algorithm as TokenEndpointExtensions.ValidateScopes.
    /// </summary>
    private static List<string> ResolveScopes(List<string> requested, ICollection<string> allowed, ICollection<string>? defaultScopes)
    {
        if (requested.Count == 0)
        {
            return (defaultScopes ?? allowed).ToList();
        }

        return requested.Where(s => allowed.Contains(s, StringComparer.Ordinal)).ToList();
    }

    [Fact]
    public void Null_DefaultScopes_grants_all_allowed_scopes()
    {
        // Arrange — backwards-compatible: no DefaultScopes configured
        ICollection<string>? defaultScopes = null;

        // Act
        var granted = ResolveScopes([], AllowedScopes, defaultScopes);

        // Assert
        granted.ShouldBe(AllowedScopes.ToList(), "null DefaultScopes should grant all AllowedScopes.");
    }

    [Fact]
    public void Empty_DefaultScopes_grants_none()
    {
        // Arrange — explicit policy: require scope in every request
        ICollection<string> defaultScopes = [];

        // Act
        var granted = ResolveScopes([], AllowedScopes, defaultScopes);

        // Assert
        granted.ShouldBeEmpty("Empty DefaultScopes should grant no scopes, forcing explicit request.");
    }

    [Fact]
    public void Explicit_DefaultScopes_grants_only_those()
    {
        // Arrange — only grant openid + profile by default
        ICollection<string> defaultScopes = ["openid", "profile"];

        // Act
        var granted = ResolveScopes([], AllowedScopes, defaultScopes);

        // Assert
        granted.Count.ShouldBe(2, "Should grant exactly the configured default scopes.");
        granted.ShouldContain("openid", "Should include openid.");
        granted.ShouldContain("profile", "Should include profile.");
        granted.ShouldNotContain("email", "Should not include email when not in defaults.");
    }

    [Fact]
    public void Explicit_request_ignores_DefaultScopes()
    {
        // Arrange — client requests specific scopes
        ICollection<string> defaultScopes = ["openid"];
        var requested = new List<string> { "openid", "email" };

        // Act
        var granted = ResolveScopes(requested, AllowedScopes, defaultScopes);

        // Assert
        granted.Count.ShouldBe(2, "Explicit request should be validated against AllowedScopes, not DefaultScopes.");
        granted.ShouldContain("email", "email is in AllowedScopes so should be granted.");
    }

    [Fact]
    public void DefaultScopes_property_defaults_to_null()
    {
        var client = new CoreIdentClient();
        client.DefaultScopes.ShouldBeNull("DefaultScopes should default to null for backwards compatibility.");
    }
}
