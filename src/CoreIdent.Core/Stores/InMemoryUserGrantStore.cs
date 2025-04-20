using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CoreIdent.Core.Models;
using System.Collections.Generic;

namespace CoreIdent.Core.Stores
{
    /// <summary>
    /// In-memory store for user consent grants.
    /// </summary>
    public class InMemoryUserGrantStore : IUserGrantStore
    {
        // Key format: "{subjectId}:{clientId}" for quick lookups
        private readonly ConcurrentDictionary<string, UserGrant> _grants = new();

        /// <summary>
        /// Clears all stored grants. Intended for test cleanup scenarios.
        /// </summary>
        public void ClearAll() => _grants.Clear();

        public Task<UserGrant?> FindAsync(string subjectId, string clientId, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(subjectId)) throw new ArgumentException(nameof(subjectId));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentException(nameof(clientId));
            var key = GetKey(subjectId, clientId);
            _grants.TryGetValue(key, out var grant);
            return Task.FromResult(grant);
        }

        public Task SaveAsync(UserGrant grant, CancellationToken cancellationToken)
        {
            if (grant == null) throw new ArgumentNullException(nameof(grant));
            
            // Ensure both SubjectId and UserId are set
            if (string.IsNullOrWhiteSpace(grant.SubjectId))
            {
                if (string.IsNullOrWhiteSpace(grant.UserId))
                    throw new ArgumentException("Either SubjectId or UserId must be provided");
                
                grant.SubjectId = grant.UserId;
            }
            else if (string.IsNullOrWhiteSpace(grant.UserId))
            {
                grant.UserId = grant.SubjectId;
            }
            
            var key = GetKey(grant.SubjectId, grant.ClientId);
            _grants.AddOrUpdate(key,
                grant,
                (k, existing) =>
                {
                    // Merge existing and new scopes
                    var merged = existing.GrantedScopes.Union(grant.GrantedScopes).ToList();
                    existing.GrantedScopes = merged;
                    existing.CreatedAt = existing.CreatedAt; // keep original timestamp
                    existing.GrantedAt = DateTime.UtcNow; // update grant time
                    return existing;
                });
            return Task.CompletedTask;
        }

        public Task StoreUserGrantAsync(string userId, string clientId, IEnumerable<string> scopes, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException(nameof(userId));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentException(nameof(clientId));
            if (scopes == null) throw new ArgumentNullException(nameof(scopes));
            
            // Create a new UserGrant with both userId and subjectId set to the same value
            var grant = new UserGrant
            {
                UserId = userId,
                SubjectId = userId, // Use userId as subjectId for consistency
                ClientId = clientId,
                Scopes = scopes.ToList(),
                GrantedScopes = scopes.ToList(), // Set both Scopes and GrantedScopes
                GrantedAt = DateTime.UtcNow
            };
            
            var key = GetKey(userId, clientId);
            _grants[key] = grant;
            return Task.CompletedTask;
        }

        public Task<bool> HasUserGrantedConsentAsync(string userId, string clientId, IEnumerable<string> scopes, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException(nameof(userId));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentException(nameof(clientId));
            if (scopes == null) throw new ArgumentNullException(nameof(scopes));
            
            var scopesList = scopes.ToList();
            var key = GetKey(userId, clientId);
            
            // First try to find by exact key
            if (_grants.TryGetValue(key, out var grant))
            {
                return Task.FromResult(scopesList.All(scope => grant.GrantedScopes.Contains(scope)));
            }
            
            // Fallback to checking by user ID through all grants
            var hasConsent = _grants.Values.Any(g => 
                (g.UserId == userId || g.SubjectId == userId) &&
                g.ClientId == clientId &&
                scopesList.All(scope => g.GrantedScopes.Contains(scope))
            );
            
            return Task.FromResult(hasConsent);
        }

        private static string GetKey(string subjectId, string clientId)
        {
            return subjectId + ":" + clientId;
        }
    }
}
