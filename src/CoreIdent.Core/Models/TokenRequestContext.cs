using System.Collections.Generic;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Models
{
    /// <summary>
    /// Context for token issuance, passed to custom claims providers.
    /// </summary>
    public class TokenRequestContext
    {
        public CoreIdentUser? User { get; set; }
        public CoreIdentClient? Client { get; set; }
        public IEnumerable<string>? Scopes { get; set; }
        public string? TokenType { get; set; } // e.g., access_token, id_token
        // Add more fields as needed (e.g., request info, claims, etc)
    }
}
