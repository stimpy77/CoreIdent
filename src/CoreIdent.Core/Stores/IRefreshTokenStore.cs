using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores;

public interface IRefreshTokenStore
{
    Task<bool> RevokeAsync(string tokenHandle, CancellationToken ct = default);
}
