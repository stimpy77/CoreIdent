namespace CoreIdent.Core.Stores;

/// <summary>
/// Exception thrown when passwordless authentication requests exceed the configured rate limit.
/// </summary>
public sealed class PasswordlessRateLimitExceededException : Exception
{
}
