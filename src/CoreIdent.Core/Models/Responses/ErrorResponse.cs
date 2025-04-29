namespace CoreIdent.Core.Models.Responses;

public class ErrorResponse
{
    public string? Message { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }
}