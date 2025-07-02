using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Api.Authentication.Core;
using Api.Authentication.Jwt;
using Api.Authentication.Jwt.Configurations;
using Api.Authentication.Jwt.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Api.Authentication.Test.Jwt;

public class CurrentUserTests
{
    private static JwtConfiguration GetJwtConfig() => new()
    {
        // HS256 requires a key of at least 256 bits (32 bytes)
        SecretKey = "supersecretkey1234567890supersecretkey!", // 32+ chars
        Issuer = "issuer",
        Audience = "audience",
        ExpirationInMinutes = 60
    };

    private static IOptions<JwtConfiguration> GetOptions() => Options.Create(GetJwtConfig());

    private static JwtConfiguration GetJwtConfigWithSession() => new()
    {
        SecretKey = "supersecretkey1234567890supersecretkey!",
        Issuer = "issuer",
        Audience = "audience",
        ExpirationInMinutes = 60,
        Session = new UserSessionConfiguration { ActivityWindowMinutes = 30 }
    };

    private static IOptions<JwtConfiguration> GetOptionsWithSession() => Options.Create(GetJwtConfigWithSession());

    private static IHttpContextAccessor GetHttpContextAccessor(IEnumerable<Claim>? claims = null)
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims ?? new List<Claim>()));
        var context = new DefaultHttpContext { User = user };
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(a => a.HttpContext).Returns(context);
        return accessor.Object;
    }

    [Fact]
    public async Task GenerateJwt_ValidClaims_ReturnsTokenResponse()
    {
        var claims = new List<CustomClaim>
        {
            new CustomClaim("sub", "user1", CustomClaimValueTypes.String, true)
        };
        var sessionManager = new Mock<ISessionManager>();
        var currentUser = new CurrentUser(GetHttpContextAccessor(), GetOptions(), sessionManager.Object);
        var response = await currentUser.GenerateJwt(claims);
        Assert.False(string.IsNullOrWhiteSpace(response.Jwt));
        Assert.Equal(60, response.ExpirationInMinutes);
    }

    [Fact]
    public async Task GenerateJwt_ThrowsIfNoUniqueClaim()
    {
        var claims = new List<CustomClaim> { new CustomClaim("sub", "user1") };
        var currentUser = new CurrentUser(GetHttpContextAccessor(), GetOptions());
        await Assert.ThrowsAsync<InvalidOperationException>(() => currentUser.GenerateJwt(claims));
    }

    [Fact]
    public async Task GenerateJwt_ThrowsIfNoClaims()
    {
        var currentUser = new CurrentUser(GetHttpContextAccessor(), GetOptions());
        await Assert.ThrowsAsync<ArgumentException>(() => currentUser.GenerateJwt(new List<CustomClaim>()));
    }

    [Fact]
    public async Task VerifyJwtAsync_ValidToken_ReturnsTrue()
    {
        var claims = new List<CustomClaim>
        {
            new CustomClaim("sub", "user1", CustomClaimValueTypes.String, true)
        };
        var currentUser = new CurrentUser(GetHttpContextAccessor(), GetOptions());
        var token = (await currentUser.GenerateJwt(claims)).Jwt;
        Assert.True(currentUser.VerifyJwtAsync(token));
    }

    [Fact]
    public void VerifyJwtAsync_InvalidToken_ReturnsFalse()
    {
        var currentUser = new CurrentUser(GetHttpContextAccessor(), GetOptions());
        Assert.False(currentUser.VerifyJwtAsync("invalid.token.value"));
    }

    [Fact]
    public async Task GetJwtClaimsAsync_ValidToken_ReturnsClaims()
    {
        var claims = new List<CustomClaim>
        {
            new CustomClaim("userId", "user1", CustomClaimValueTypes.String, true)
        };
        var currentUser = new CurrentUser(GetHttpContextAccessor(), GetOptions());
        var token = (await currentUser.GenerateJwt(claims)).Jwt;
        var jwtClaims = currentUser.GetJwtClaimsAsync(token);
        Assert.Contains(jwtClaims, c => c.Type == "userId" && c.Value == "user1");
    }

    [Fact]
    public void GetJwtClaimsAsync_InvalidToken_ReturnsEmptyList()
    {
        var currentUser = new CurrentUser(GetHttpContextAccessor(), GetOptions());
        var claims = currentUser.GetJwtClaimsAsync("invalid.token.value");
        Assert.Empty(claims);
    }

    [Fact]
    public async Task RevokeJwtAsync_CallsSessionManagerRemoveAsync()
    {
        var claims = new List<Claim> { new Claim("identifyer", "user1") };
        var sessionManager = new Mock<ISessionManager>();
        sessionManager.Setup(m => m.RemoveAsync("user1")).Returns(Task.CompletedTask).Verifiable();
        var currentUser = new CurrentUser(GetHttpContextAccessor(claims), GetOptionsWithSession(), sessionManager.Object);
        await currentUser.RevokeJwtAsync();
        sessionManager.Verify();
    }

    [Fact]
    public void RevokeJwtAsync_ThrowsIfNoSessionManager()
    {
        Assert.Throws<NullReferenceException>(() => new CurrentUser(GetHttpContextAccessor(), GetOptionsWithSession()));
    }
}
