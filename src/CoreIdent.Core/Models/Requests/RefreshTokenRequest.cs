using System.ComponentModel.DataAnnotations;

namespace CoreIdent.Core.Models.Requests;

/// <summary>
/// DTO for the token refresh request.
/// </summary>
public record RefreshTokenRequest
{
    [Required(ErrorMessage = "Refresh token is required.")]
    public string? RefreshToken { get; init; }
}
