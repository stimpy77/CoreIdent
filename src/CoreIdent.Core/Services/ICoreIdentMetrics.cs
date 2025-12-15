namespace CoreIdent.Core.Services;

public interface ICoreIdentMetrics
{
    void ClientAuthenticated(string clientType, bool success, double elapsedMilliseconds);
    void TokenIssued(string tokenType, string grantType, double elapsedMilliseconds);
    void TokenRevoked(string tokenType);
}

public sealed class NullCoreIdentMetrics : ICoreIdentMetrics
{
    public void ClientAuthenticated(string clientType, bool success, double elapsedMilliseconds) { }

    public void TokenIssued(string tokenType, string grantType, double elapsedMilliseconds) { }

    public void TokenRevoked(string tokenType) { }
}
