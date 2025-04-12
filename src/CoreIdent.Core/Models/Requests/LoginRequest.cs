using System.ComponentModel.DataAnnotations;

namespace CoreIdent.Core.Models.Requests;

/// <summary>
/// DTO for the user login request.
/// </summary>
public record LoginRequest
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address format.")]
    public string? Email { get; init; }

    [Required(ErrorMessage = "Password is required.")]
    public string? Password { get; init; }
}
