namespace CoreIdent.Core.Tests.TestUtilities;

/// <summary>
/// A mutable time provider for testing time-dependent logic.
/// </summary>
public sealed class MutableTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;

    public MutableTimeProvider(DateTimeOffset utcNow)
    {
        _utcNow = utcNow;
    }

    /// <summary>
    /// Advances the current time by the specified duration.
    /// </summary>
    public void Advance(TimeSpan delta)
    {
        _utcNow = _utcNow.Add(delta);
    }

    /// <summary>
    /// Sets the current time to a specific value.
    /// </summary>
    public void SetUtcNow(DateTimeOffset utcNow)
    {
        _utcNow = utcNow;
    }

    public override DateTimeOffset GetUtcNow() => _utcNow;
}
