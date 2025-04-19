using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Services
{
    /// <summary>
    /// Default implementation of ICustomClaimsProvider that returns no custom claims.
    /// </summary>
    public class CustomClaimsProviderDefault : ICustomClaimsProvider
    {
        public Task<IEnumerable<Claim>> GetCustomClaimsAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            return Task.FromResult<IEnumerable<Claim>>(new List<Claim>());
        }
    }
}
