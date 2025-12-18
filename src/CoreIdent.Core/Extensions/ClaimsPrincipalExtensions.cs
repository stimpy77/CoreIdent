using System.Security.Claims;

namespace CoreIdent.Core.Extensions;

/// <summary>
/// Convenience extensions for working with a <see cref="ClaimsPrincipal"/>.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    extension(ClaimsPrincipal principal)
    {
        /// <summary>
        /// Gets the email claim value if present.
        /// </summary>
        public string? Email =>
            principal.FindFirstValue(ClaimTypes.Email) ?? principal.FindFirstValue("email");

        /// <summary>
        /// Gets the user identifier claim value if present.
        /// </summary>
        public string? UserId =>
            principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? principal.FindFirstValue("sub");

        /// <summary>
        /// Gets the display name claim value if present.
        /// </summary>
        public string? Name =>
            principal.FindFirstValue(ClaimTypes.Name) ?? principal.FindFirstValue("name");

        /// <summary>
        /// Parses <see cref="UserId"/> as a <see cref="Guid"/>.
        /// </summary>
        /// <returns>The parsed GUID.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the claim is missing or not a valid GUID.</exception>
        public Guid GetUserIdAsGuid()
        {
            var id = principal.UserId;
            if (string.IsNullOrWhiteSpace(id) || !Guid.TryParse(id, out var guid))
            {
                throw new InvalidOperationException("User ID is not a valid GUID");
            }

            return guid;
        }

        /// <summary>
        /// Gets a claim and parses it as <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">The target type.</typeparam>
        /// <param name="claimType">The claim type.</param>
        /// <returns>The parsed value, or <see langword="default"/> if missing/blank.</returns>
        public T? GetClaim<T>(string claimType) where T : IParsable<T>
        {
            var value = principal.FindFirstValue(claimType);
            if (string.IsNullOrWhiteSpace(value))
            {
                return default;
            }

            try
            {
                return T.Parse(value, null);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Claim '{claimType}' could not be parsed as {typeof(T).Name}.", ex);
            }
        }

        /// <summary>
        /// Gets the set of role values for the principal.
        /// </summary>
        /// <returns>Role values.</returns>
        public IEnumerable<string> GetRoles()
        {
            var roleClaimType = (principal.Identity as ClaimsIdentity)?.RoleClaimType ?? ClaimTypes.Role;

            return principal.Claims
                .Where(c => c.Type == roleClaimType || c.Type == ClaimTypes.Role || c.Type == "role")
                .Select(c => c.Value);
        }

        /// <summary>
        /// Determines if the principal is in a role using a specific string comparison.
        /// </summary>
        /// <param name="role">Role to check.</param>
        /// <param name="comparisonType">String comparison type.</param>
        /// <returns><see langword="true"/> if the role is present; otherwise <see langword="false"/>.</returns>
        public bool IsInRole(string role, StringComparison comparisonType)
        {
            if (string.IsNullOrWhiteSpace(role))
            {
                return false;
            }

            var roleClaimType = (principal.Identity as ClaimsIdentity)?.RoleClaimType ?? ClaimTypes.Role;
            var roles = principal.Claims
                .Where(c => c.Type == roleClaimType || c.Type == ClaimTypes.Role || c.Type == "role")
                .Select(c => c.Value);

            return roles.Any(r => string.Equals(r, role, comparisonType));
        }
    }
}
