using System.Threading.Tasks;
using Xunit;
using Moq;
using Shouldly;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using System;

namespace CoreIdent.Core.Tests.Services
{
    public class AuthorizationCodeServiceTests
    {
        [Fact]
        public async Task StoreAuthorizationCodeAsync_Saves_Code()
        {
            // Arrange
            var codeStore = new Mock<IAuthorizationCodeStore>();
            var code = new AuthorizationCode {
                CodeHandle = "authcode1",
                ClientId = "client1",
                SubjectId = "user1",
                RedirectUri = "http://localhost/callback",
                CreationTime = DateTime.UtcNow,
                ExpirationTime = DateTime.UtcNow.AddMinutes(5)
            };
            codeStore.Setup(x => x.StoreAuthorizationCodeAsync(code, default)).ReturnsAsync(StoreResult.Success);

            // Act
            var result = await codeStore.Object.StoreAuthorizationCodeAsync(code, default);

            // Assert
            result.ShouldBe(StoreResult.Success);
        }
    }
}
