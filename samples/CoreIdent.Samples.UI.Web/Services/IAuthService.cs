using System.Threading.Tasks;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Models.Responses;

namespace CoreIdent.Samples.UI.Web.Services
{
    public interface IAuthService
    {
        Task<TokenResponse?> LoginAsync(LoginRequest request);
        Task<bool> RegisterAsync(RegisterRequest request);
        Task<bool> ConsentAsync(ConsentRequest request);
    }
}
