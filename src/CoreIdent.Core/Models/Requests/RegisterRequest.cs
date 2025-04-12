using System.ComponentModel.DataAnnotations; // For validation attributes

namespace CoreIdent.Core.Models.Requests;

/// <summary>
/// DTO for the user registration request.
/// </summary>
public record RegisterRequest
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address format.")]
    public string? Email { get; init; }

    [Required(ErrorMessage = "Password is required.")]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters long.")] // Basic complexity, can be enhanced
    // Consider adding regex for more complexity if needed:
    // [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
    //     ErrorMessage = "Password must contain uppercase, lowercase, digit, and special character.")]
    public string? Password { get; init; }
}
