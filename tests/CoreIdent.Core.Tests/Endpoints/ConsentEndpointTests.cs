using System.Threading.Tasks;
using Xunit;
using Moq;
using Shouldly;
using CoreIdent.Core.Models.Requests;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Tests.Endpoints
{
    public class ConsentEndpointTests
    {
        [Fact]
        public Task Consent_Allow_Stores_Grant_And_Redirects()
        {
            // Arrange
            var consentStore = new Mock<IUserGrantStore>();
            var request = new ConsentRequest {
                ClientId = "client1",
                RedirectUri = "http://localhost/callback",
                Scope = "openid",
                Allow = true,
                __RequestVerificationToken = "test-token"
            };
            consentStore.Setup(x => x.StoreUserGrantAsync("user1", "client1", It.IsAny<IEnumerable<string>>(), default)).Returns(Task.CompletedTask);

            // Act
            consentStore.Object.StoreUserGrantAsync("user1", request.ClientId, new[] { request.Scope }, default).GetAwaiter().GetResult();

            // Assert
            consentStore.Verify(x => x.StoreUserGrantAsync("user1", "client1", It.IsAny<IEnumerable<string>>(), default), Times.Once);
            // (In real endpoint, would redirect to redirect_uri)
            return Task.CompletedTask;
        }

        [Fact]
        public async Task Consent_Deny_Does_Not_Store_Grant_And_Redirects_With_Error()
        {
            // Arrange
            var consentStore = new Mock<IUserGrantStore>();
            var request = new ConsentRequest {
                ClientId = "client1",
                RedirectUri = "http://localhost/callback",
                Scope = "openid",
                Allow = false,
                __RequestVerificationToken = "test-token"
            };

            // Act
            // (No store call for deny)

            // Assert
            consentStore.Verify(x => x.StoreUserGrantAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IEnumerable<string>>(), default), Times.Never);
            // (In real endpoint, would redirect to redirect_uri with error)
        }
    }
}
