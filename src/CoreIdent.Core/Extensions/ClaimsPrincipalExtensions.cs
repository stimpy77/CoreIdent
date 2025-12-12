using System.Security.Claims;

namespace CoreIdent.Core.Extensions;

public static class ClaimsPrincipalExtensions
{
    extension(ClaimsPrincipal principal)
    {
        public string? Email =>
            principal.FindFirstValue(ClaimTypes.Email) ?? principal.FindFirstValue("email");

        public string? UserId =>
            principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? principal.FindFirstValue("sub");

        public string? Name =>
            principal.FindFirstValue(ClaimTypes.Name) ?? principal.FindFirstValue("name");

        public Guid GetUserIdAsGuid()
        {
            var id = principal.UserId;
            if (string.IsNullOrWhiteSpace(id) || !Guid.TryParse(id, out var guid))
            {
                throw new InvalidOperationException("User ID is not a valid GUID");
            }

            return guid;
        }

        public T? GetClaim<T>(string claimType) where T : struct, IParsable<T>
        {
            var value = principal.FindFirstValue(claimType);
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
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

        public IEnumerable<string> GetRoles()
        {
            var roleClaimType = (principal.Identity as ClaimsIdentity)?.RoleClaimType ?? ClaimTypes.Role;

            return principal.Claims
                .Where(c => c.Type == roleClaimType || c.Type == ClaimTypes.Role || c.Type == "role")
                .Select(c => c.Value);
        }

        public bool HasRole(string role, StringComparison comparisonType = StringComparison.OrdinalIgnoreCase) =>
            !string.IsNullOrWhiteSpace(role) &&
            principal.GetRoles().Any(r => string.Equals(r, role, comparisonType));
    }
}
