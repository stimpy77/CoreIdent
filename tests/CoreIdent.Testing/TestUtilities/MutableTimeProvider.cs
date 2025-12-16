namespace CoreIdent.Testing.TestUtilities;

public sealed class MutableTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;

    public MutableTimeProvider(DateTimeOffset utcNow)
    {
        _utcNow = utcNow;
    }

    public void Advance(TimeSpan delta)
    {
        _utcNow = _utcNow.Add(delta);
    }

    public override DateTimeOffset GetUtcNow() => _utcNow;
}
