using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Services
{
    /// <summary>
    /// Provides an extensibility point for injecting custom claims into issued tokens.
    /// </summary>
    public interface ICustomClaimsProvider
    {
        /// <summary>
        /// Returns custom claims to be included in the token for the given context.
        /// </summary>
        /// <param name="context">Token issuance context (user, client, scopes, etc).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Enumerable of additional claims to include.</returns>
        Task<IEnumerable<Claim>> GetCustomClaimsAsync(TokenRequestContext context, CancellationToken cancellationToken);
    }
}
