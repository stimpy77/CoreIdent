using CoreIdent.Core.Models;

namespace CoreIdent.Core.Services;

public interface IPasswordHasher
{
    string HashPassword(CoreIdentUser user, string password);

    bool VerifyHashedPassword(CoreIdentUser user, string hashedPassword, string providedPassword);
}
