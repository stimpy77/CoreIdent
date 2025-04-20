using System.ComponentModel.DataAnnotations;

namespace CoreIdent.Core.Models.Requests
{
    /// <summary>
    /// DTO for user consent decisions.
    /// </summary>
    public class ConsentRequest
    {
        [Required]
        public string ClientId { get; set; } = default!;

        [Required]
        public string RedirectUri { get; set; } = default!;

        [Required]
        public string Scope { get; set; } = default!;

        public string? State { get; set; }

        /// <summary>
        /// URL to redirect back after consent decision (authorization endpoint with parameters).
        /// </summary>
        public string ReturnUrl { get; set; } = default!;

        /// <summary>
        /// True if the user allowed consent; false if denied.
        /// </summary>
        public bool Allow { get; set; }

        /// <summary>
        /// Hidden antiforgery token field
        /// </summary>
        [Required]
        public string __RequestVerificationToken { get; set; } = default!;
    }
}
