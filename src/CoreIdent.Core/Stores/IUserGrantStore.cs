using System.Threading;
using System.Threading.Tasks;
using CoreIdent.Core.Models;
using System.Collections.Generic;

namespace CoreIdent.Core.Stores
{
    /// <summary>
    /// Abstraction for user consent grants store.
    /// </summary>
    public interface IUserGrantStore
    {
        /// <summary>
        /// Finds an existing grant for the subject and client.
        /// </summary>
        Task<UserGrant?> FindAsync(string subjectId, string clientId, CancellationToken cancellationToken);

        /// <summary>
        /// Saves or updates a user consent grant.
        /// </summary>
        Task SaveAsync(UserGrant grant, CancellationToken cancellationToken);

        /// <summary>
        /// Stores a user grant.
        /// </summary>
        Task StoreUserGrantAsync(string userId, string clientId, IEnumerable<string> scopes, CancellationToken cancellationToken);

        /// <summary>
        /// Checks if a user has granted consent for the specified scopes.
        /// </summary>
        Task<bool> HasUserGrantedConsentAsync(string userId, string clientId, IEnumerable<string> scopes, CancellationToken cancellationToken);
    }
}
