namespace CoreIdent.Core.Services;

/// <summary>
/// Records CoreIdent metrics.
/// </summary>
public interface ICoreIdentMetrics
{
    /// <summary>
    /// Records a client authentication attempt.
    /// </summary>
    /// <param name="clientType">The client type (e.g. public/confidential).</param>
    /// <param name="success">Whether authentication succeeded.</param>
    /// <param name="elapsedMilliseconds">Elapsed time in milliseconds.</param>
    void ClientAuthenticated(string clientType, bool success, double elapsedMilliseconds);

    /// <summary>
    /// Records token issuance.
    /// </summary>
    /// <param name="tokenType">The token type.</param>
    /// <param name="grantType">The OAuth grant type.</param>
    /// <param name="elapsedMilliseconds">Elapsed time in milliseconds.</param>
    void TokenIssued(string tokenType, string grantType, double elapsedMilliseconds);

    /// <summary>
    /// Records token revocation.
    /// </summary>
    /// <param name="tokenType">The token type.</param>
    void TokenRevoked(string tokenType);
}

/// <summary>
/// No-op metrics implementation.
/// </summary>
public sealed class NullCoreIdentMetrics : ICoreIdentMetrics
{
    /// <inheritdoc />
    public void ClientAuthenticated(string clientType, bool success, double elapsedMilliseconds) { }

    /// <inheritdoc />
    public void TokenIssued(string tokenType, string grantType, double elapsedMilliseconds) { }

    /// <inheritdoc />
    public void TokenRevoked(string tokenType) { }
}
