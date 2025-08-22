using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Api.Security.Authentication.Scheme;
using Api.Security.Authentication.Scheme.Handlers;
using Api.Security.Authentication.Scheme.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Shouldly;
using Xunit;

namespace Api.Security.Authentication.Scheme.Test;

public class BasicAuthenticationHandler_HandleAuthenticateAsync_Should
{
    private static BasicAuthenticationHandler CreateHandler(Mock<IBasicAuthenticationService> authServiceMock, HttpContext httpContext)
    {
        var options = new Mock<IOptionsMonitor<AuthenticationSchemeOptions>>();
        options.Setup(o => o.Get(It.IsAny<string>())).Returns(new AuthenticationSchemeOptions());
        var loggerFactory = new LoggerFactory();
        var encoder = UrlEncoder.Default;
        var handler = new BasicAuthenticationHandler(options.Object, loggerFactory, encoder, authServiceMock.Object);
        handler.InitializeAsync(new AuthenticationScheme("Basic", null, typeof(BasicAuthenticationHandler)), httpContext);
        return handler;
    }

    [Fact]
    public async Task ReturnFail_WhenAuthorizationHeaderIsMissing()
    {
        // Arrange
        var authServiceMock = new Mock<IBasicAuthenticationService>(MockBehavior.Strict);
        var context = new DefaultHttpContext();
        var handler = CreateHandler(authServiceMock, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldNotBeNull();
        result.Failure!.Message.ShouldBe("Missing Authorization Header");
    }

    [Fact]
    public async Task ReturnFail_WhenAuthorizationHeaderIsMalformed()
    {
        // Arrange
        var authServiceMock = new Mock<IBasicAuthenticationService>(MockBehavior.Strict);
        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "Basic not_base64";
        var handler = CreateHandler(authServiceMock, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldNotBeNull();
        result.Failure!.Message.ShouldBe("Invalid Authorization Header");
    }

    [Fact]
    public async Task ReturnFail_WhenCredentialsAreInvalid()
    {
        // Arrange
        var authServiceMock = new Mock<IBasicAuthenticationService>(MockBehavior.Strict);
        authServiceMock.Setup(s => s.Authenticate("user", "wrongpass"))
            .ReturnsAsync(new AuthResponse(false));
        var context = new DefaultHttpContext();
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:wrongpass"));
        context.Request.Headers["Authorization"] = $"Basic {credentials}";
        var handler = CreateHandler(authServiceMock, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldNotBeNull();
        result.Failure!.Message.ShouldBe("Invalid Username or Password");
    }

    [Fact]
    public async Task ReturnSuccess_WithDefaultClaims_WhenCredentialsAreValid_AndNoCustomClaims()
    {
        // Arrange
        var authServiceMock = new Mock<IBasicAuthenticationService>(MockBehavior.Strict);
        authServiceMock.Setup(s => s.Authenticate("user", "pass"))
            .ReturnsAsync(new AuthResponse(true));
        var context = new DefaultHttpContext();
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"));
        context.Request.Headers["Authorization"] = $"Basic {credentials}";
        var handler = CreateHandler(authServiceMock, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Succeeded.ShouldBeTrue();
        var principal = result.Principal;
        principal.ShouldNotBeNull();
        principal!.Identities.ShouldContain(i => i.Name == "user");
        principal.Claims.ShouldContain(c => c.Type == ClaimTypes.NameIdentifier && c.Value == "user");
        principal.Claims.ShouldContain(c => c.Type == ClaimTypes.Name && c.Value == "user");
    }

    [Fact]
    public async Task ReturnSuccess_WithCustomClaims_WhenCredentialsAreValid_AndCustomClaimsProvided()
    {
        // Arrange
        var claims = new Dictionary<string, string> { { "role", "admin" }, { "email", "user@example.com" } };
        var authServiceMock = new Mock<IBasicAuthenticationService>(MockBehavior.Strict);
        authServiceMock.Setup(s => s.Authenticate("user", "pass"))
            .ReturnsAsync(new AuthResponse(true, claims));
        var context = new DefaultHttpContext();
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"));
        context.Request.Headers["Authorization"] = $"Basic {credentials}";
        var handler = CreateHandler(authServiceMock, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Succeeded.ShouldBeTrue();
        var principal = result.Principal;
        principal.ShouldNotBeNull();
        principal!.Claims.ShouldContain(c => c.Type == "role" && c.Value == "admin");
        principal.Claims.ShouldContain(c => c.Type == "email" && c.Value == "user@example.com");
    }

    [Fact]
    public async Task ReturnFail_WhenExceptionIsThrown()
    {
        // Arrange
        var authServiceMock = new Mock<IBasicAuthenticationService>(MockBehavior.Strict);
        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "Basic badheader";
        var handler = CreateHandler(authServiceMock, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldNotBeNull();
        result.Failure!.Message.ShouldBe("Invalid Authorization Header");
    }
}
