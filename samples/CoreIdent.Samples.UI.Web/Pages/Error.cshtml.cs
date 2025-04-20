using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;

namespace CoreIdent.Samples.UI.Web.Pages
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [IgnoreAntiforgeryToken]
    [Microsoft.AspNetCore.Authorization.AllowAnonymous]
    public class ErrorModel : PageModel
    {
        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        public string? ErrorMessage { get; set; }

        public void OnGet(string? message = null)
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
            ErrorMessage = message;
        }

        public void OnPost(string? message = null)
        {
             RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
             ErrorMessage = message;
        }
    }
} 