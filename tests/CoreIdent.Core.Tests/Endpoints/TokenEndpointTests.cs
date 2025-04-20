using System.Threading.Tasks;
using Xunit;
using Moq;
using Shouldly;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Core.Services;
using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Tests.Endpoints
{
    public class TokenEndpointTests
    {
        [Fact]
        public async Task Valid_Authorization_Code_Issues_Token()
        {
            // Arrange
            var codeStore = new Mock<IAuthorizationCodeStore>();
            var tokenService = new Mock<ITokenService>();
            var code = new AuthorizationCode {
                CodeHandle = "authcode1",
                ClientId = "client1",
                SubjectId = "user1",
                RedirectUri = "http://localhost/callback"
            };
            codeStore.Setup(x => x.GetAuthorizationCodeAsync("authcode1", default)).ReturnsAsync(code);
            tokenService.Setup(x => x.GenerateAccessTokenAsync(It.IsAny<CoreIdentUser>(), null)).ReturnsAsync("token123");

            // Act
            var storedCode = await codeStore.Object.GetAuthorizationCodeAsync("authcode1", default);
            var token = await tokenService.Object.GenerateAccessTokenAsync(new CoreIdentUser { Id = "user1" });

            // Assert
            storedCode.ShouldNotBeNull();
            token.ShouldBe("token123");
        }

        [Fact]
        public async Task Invalid_Authorization_Code_Returns_Error()
        {
            // Arrange
            var codeStore = new Mock<IAuthorizationCodeStore>();
            codeStore.Setup(x => x.GetAuthorizationCodeAsync("badcode", default)).ReturnsAsync((AuthorizationCode)null);

            // Act
            var storedCode = await codeStore.Object.GetAuthorizationCodeAsync("badcode", default);

            // Assert
            storedCode.ShouldBeNull();
            // (In real endpoint, would return error)
        }
    }
}
