using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Testing.Builders;

public sealed class UserBuilder
{
    private string _id = Guid.NewGuid().ToString("N");
    private string _email = $"user-{Guid.NewGuid():N}@test.local";

    public List<Claim> Claims { get; } = [];

    public string? Password { get; private set; }

    public UserBuilder WithId(string id)
    {
        _id = id;
        return this;
    }

    public UserBuilder WithEmail(string email)
    {
        _email = email;
        return this;
    }

    public UserBuilder WithPassword(string password)
    {
        Password = password;
        return this;
    }

    public UserBuilder WithClaim(string type, string value)
    {
        Claims.Add(new Claim(type, value));
        return this;
    }

    public CoreIdentUser Build() => new()
    {
        Id = _id,
        UserName = _email,
        NormalizedUserName = _email.Trim().ToUpperInvariant(),
        CreatedAt = DateTime.UtcNow
    };
}
