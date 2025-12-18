namespace CoreIdent.Core.Services.Realms;

/// <summary>
/// Provides access to the current realm context for realm-aware operations.
/// </summary>
public interface ICoreIdentRealmContext
{
    /// <summary>
    /// Gets the current realm identifier.
    /// </summary>
    string RealmId { get; }
}
