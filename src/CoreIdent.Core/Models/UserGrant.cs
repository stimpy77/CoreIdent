using System;
using System.Collections.Generic;

namespace CoreIdent.Core.Models
{
    /// <summary>
    /// Represents a user's consent grant for a client.
    /// </summary>
    public class UserGrant
    {
        public int Id { get; set; }

        /// <summary>
        /// The subject (user) identifier.
        /// </summary>
        public string SubjectId { get; set; } = default!;

        /// <summary>
        /// The user identifier.
        /// </summary>
        public string UserId { get; set; } = default!;

        /// <summary>
        /// The client that the user granted consent to.
        /// </summary>
        public string ClientId { get; set; } = default!;

        /// <summary>
        /// The scopes the user granted.
        /// </summary>
        public List<string> GrantedScopes { get; set; } = new List<string>();

        /// <summary>
        /// The scopes the user is granting.
        /// </summary>
        public List<string> Scopes { get; set; } = new();

        /// <summary>
        /// Timestamp when the grant was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Timestamp when the grant was granted.
        /// </summary>
        public DateTime GrantedAt { get; set; }
    }
}
