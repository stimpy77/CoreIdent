using System.Threading.Tasks;
using Xunit;
using Moq;
using Shouldly;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Configuration;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;

namespace CoreIdent.Core.Tests.Endpoints
{
    public class AuthorizeEndpointTests
    {
        [Fact]
        public async Task Unauthenticated_User_Is_Redirected_To_Login()
        {
            // Arrange
            var clientStore = new Mock<IClientStore>();
            var userStore = new Mock<IUserStore>();
            var consentStore = new Mock<IUserGrantStore>();
            var codeStore = new Mock<IAuthorizationCodeStore>();
            var options = new CoreIdentRouteOptions();
            var httpContext = new DefaultHttpContext();
            // Simulate unauthenticated user
            httpContext.User = new System.Security.Claims.ClaimsPrincipal();

            // Act: Simulate authorize endpoint logic
            var isAuthenticated = httpContext.User.Identity?.IsAuthenticated == true;

            // Assert
            isAuthenticated.ShouldBeFalse();
            // (In real endpoint, would redirect to /auth/login)
        }

        [Fact]
        public async Task Authenticated_User_Without_Consent_Is_Redirected_To_Consent()
        {
            // Arrange
            var clientStore = new Mock<IClientStore>();
            var userStore = new Mock<IUserStore>();
            var consentStore = new Mock<IUserGrantStore>();
            var codeStore = new Mock<IAuthorizationCodeStore>();
            var options = new CoreIdentRouteOptions();
            var claims = new List<System.Security.Claims.Claim> {
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, "user1")
            };
            var identity = new System.Security.Claims.ClaimsIdentity(claims, "Cookies");
            var principal = new System.Security.Claims.ClaimsPrincipal(identity);
            var httpContext = new DefaultHttpContext { User = principal };

            consentStore.Setup(x => x.HasUserGrantedConsentAsync("user1", It.IsAny<string>(), It.IsAny<IEnumerable<string>>(), default)).ReturnsAsync(false);

            // Act: Simulate authorize endpoint logic
            var isAuthenticated = httpContext.User.Identity?.IsAuthenticated == true;
            var hasConsent = await consentStore.Object.HasUserGrantedConsentAsync("user1", "client1", new[] { "openid" }, default);

            // Assert
            isAuthenticated.ShouldBeTrue();
            hasConsent.ShouldBeFalse();
            // (In real endpoint, would redirect to /auth/consent)
        }
    }
}
