using CoreIdent.Core.Configuration;
using System;
using Xunit;

namespace CoreIdent.Core.Tests.Configuration
{
    public class CoreIdentRouteOptionsTests
    {
        [Theory]
        [InlineData("/auth", "./token", "/auth/token")]
        [InlineData("/auth", "../token", "/token")]
        [InlineData("/auth/", "../token", "/token")]
        [InlineData("/auth/", "./token", "/auth/token")]
        [InlineData("/auth/", "token", "/auth/token")]
        [InlineData("/", "../token", "/token")]
        public void Combine_NormalizesDotSegments(string basePath, string relativePath, string expected)
        {
            var options = new CoreIdentRouteOptions { BasePath = basePath };
            var result = options.Combine(relativePath);
            Assert.Equal(expected, result);
        }
    }
}
