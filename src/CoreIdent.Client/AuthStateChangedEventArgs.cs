namespace CoreIdent.Client;

/// <summary>
/// Event arguments for <see cref="ICoreIdentClient.AuthStateChanged"/>.
/// </summary>
public sealed class AuthStateChangedEventArgs : EventArgs
{
    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public AuthStateChangedEventArgs(bool isAuthenticated)
    {
        IsAuthenticated = isAuthenticated;
    }

    /// <summary>
    /// Gets whether the client is authenticated.
    /// </summary>
    public bool IsAuthenticated { get; }
}
