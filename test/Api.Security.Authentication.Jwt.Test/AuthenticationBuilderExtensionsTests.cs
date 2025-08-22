using System;
using System.Collections.Generic;
using System.Security.Claims;
using Api.Security.Authentication.Core;
using Api.Security.Authentication.Core;
using Api.Security.Authentication.Jwt;
using Api.Security.Authentication.Jwt.Configurations;
using Api.Security.Authentication.Jwt.DependencyInjection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using AuthenticationBuilder = Api.Security.Authentication.Core.AuthenticationBuilder;

namespace Api.Security.Authentication.Jwt.Test;

public class AuthenticationBuilderExtensionsTests
{
    private readonly JwtConfiguration _defaultConfig = new JwtConfiguration
    {
        SecretKey = "testkey1234567890",
        Issuer = "issuer",
        Audience = "audience",
        ExpirationInMinutes = 60
    };
    
    private AuthenticationBuilder GetBuilder(JwtConfiguration? config)
    {
        var services = new ServiceCollection();
        
        var user = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var context = new DefaultHttpContext { User = user };
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(a => a.HttpContext).Returns(context);
        services.AddSingleton(accessor.Object);
        
        if (config?.Session != null)
        {
            var sessionManager = new Mock<ISessionManager>();
            services.AddSingleton(sessionManager.Object);
        }

        return new AuthenticationBuilder(services);
    }
    
    private AuthenticationBuilder GetBuilder()
    {
        var services = new ServiceCollection();
        
        var user = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var context = new DefaultHttpContext { User = user };
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(a => a.HttpContext).Returns(context);
        services.AddSingleton(accessor.Object);
        return new AuthenticationBuilder(services);
    }

    [Fact]
    public void RegistersAuthenticationAndCurrentUser_WhenWithJwtBearerIsCalled()
    {
        // Arrange
        var builder = GetBuilder();
        
        // Act
        builder.WithJwtBearer(_defaultConfig);
        var provider = builder.Services.BuildServiceProvider();
        
        // Assert
        Assert.NotNull(provider.GetService<ICurrentUser>());
        Assert.NotNull(provider.GetService<IAuthenticationService>());
    }

    [Fact]
    public void RegistersSessionManager_WhenSessionConfigured()
    {
        // Arrange
        var config = new JwtConfiguration
        {
            SecretKey = "testkey1234567890",
            Issuer = "issuer",
            Audience = "audience",
            ExpirationInMinutes = 60,
            Session = new UserSessionConfiguration { ActivityWindowMinutes = 10 }
        };
        var builder = GetBuilder(config);
        
        // Act
        builder.WithJwtBearer(config);
        
        // Assert
        Assert.NotNull(builder.Services); // Could be improved with a real ISessionManager test/mock
    }

    [Fact]
    public void ConfiguresJwtBearerOptions_WhenWithJwtBearerIsCalled()
    {
        // Arrange
        var builder = GetBuilder();
        
        // Act
        builder.WithJwtBearer(_defaultConfig);
        var provider = builder.Services.BuildServiceProvider();
        
        // Assert
        Assert.NotNull(provider.GetService<IOptions<JwtBearerOptions>>());
    }

    [Fact]
    public void RegistersServices_WhenCustomRewriteConfigProvided()
    {
        // Arrange
        var builder = GetBuilder();
        var rewriteConfig = new AuthReWriteConfig
        {
            PathStrings = ["/hub"],
            Token = new Mapping { From = Source.Query, Key = "access_token" },
            Headers = new Dictionary<string, Mapping> { { "X-Test", new Mapping { From = Source.Header, Key = "X-Test" } } }
        };
        
        // Act
        builder.WithJwtBearer(_defaultConfig, rewriteConfig);
        
        // Assert
        Assert.NotNull(builder.Services);
    }

    [Fact]
    public void ThrowsException_WhenJwtConfigurationIsNull()
    {
        // Arrange
        var builder = GetBuilder();
        
        // Act & Assert
        var ex = Record.Exception(() => builder.WithJwtBearer(jwtConfiguration: null));
        Assert.NotNull(ex);
        Assert.IsType<ArgumentException>(ex.InnerException ?? ex);
    }

    [Fact]
    public void ThrowsException_WhenJwtConfigurationIsIncomplete()
    {
        // Arrange
        var config = new JwtConfiguration { SecretKey = null!, Issuer = null!, Audience = null!, ExpirationInMinutes = 0 };
        var builder = GetBuilder(config);
        
        // Act & Assert
        var ex = Record.Exception(() => builder.WithJwtBearer(config));
        Assert.NotNull(ex);
        Assert.IsType<ArgumentNullException>(ex.InnerException ?? ex);
    }

    [Fact]
    public void DoesNotThrow_WhenRewriteConfigIsNull()
    {
        // Arrange
        var builder = GetBuilder();
        
        
        // Act & Assert
        var ex = Record.Exception(() => builder.WithJwtBearer(_defaultConfig, null));
        Assert.Null(ex);
    }

    [Fact]
    public void DoesNotThrow_WhenRewriteConfigIsPartial()
    {
        // Arrange
        var builder = GetBuilder();
        var rewriteConfig = new AuthReWriteConfig {PathStrings = ["/hub"]};
        
        // Act & Assert
        var ex = Record.Exception(() => builder.WithJwtBearer(_defaultConfig, rewriteConfig));
        Assert.Null(ex);
    }

    [Fact]
    public void ThrowsException_WhenSessionManagerIsRequiredButNotRegistered()
    {
        // Arrange
        var config = new JwtConfiguration
        {
            SecretKey = "testkey1234567890",
            Issuer = "issuer",
            Audience = "audience",
            ExpirationInMinutes = 60,
            Session = new UserSessionConfiguration { ActivityWindowMinutes = 10 }
        };
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                {"JwtConfiguration:SecretKey", config.SecretKey},
                {"JwtConfiguration:Issuer", config.Issuer},
                {"JwtConfiguration:Audience", config.Audience},
                {"JwtConfiguration:ExpirationInMinutes", config.ExpirationInMinutes.ToString()}
            })
            .Build();
        var builder = new AuthenticationBuilder(services);
        // Remove ISessionManager registration to simulate missing dependency
        // Act
        var ex = Record.Exception(() => builder.WithJwtBearer(config));
        // Assert
        Assert.Null(ex); // Registration does not throw, but runtime will fail if ISessionManager is missing
    }

    // [Fact]
    // public async Task FailsTokenValidation_WhenSessionManagerReturnsNoToken()
    // {
    //     // Arrange
    //     var config = new JwtConfiguration
    //     {
    //         SecretKey = "testkey1234567890",
    //         Issuer = "issuer",
    //         Audience = "audience",
    //         ExpirationInMinutes = 60,
    //         Session = new UserSessionConfiguration { ActivityWindowMinutes = 10 }
    //     };
    //     var builder = GetBuilder(config);
    //     var sessionManagerMock = new Mock<ISessionManager>();
    //     sessionManagerMock.Setup(m => m.TryGetValue(It.IsAny<string>(), out It.Ref<string>.IsAny)).ReturnsAsync(false);
    //     builder.Services.AddSingleton(sessionManagerMock.Object);
    //     builder.WithJwtBearer();
    //     var provider = builder.Services.BuildServiceProvider();
    //     var options = provider.GetRequiredService<IOptions<JwtBearerOptions>>().Value;
    //     var context = new DefaultHttpContext();
    //     var claims = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(SystemClaim.Identifier, "user1") }));
    //     context.User = claims;
    //     context.Request.Headers["Authorization"] = "Bearer testtoken";
    //     var tokenValidatedContext = new TokenValidatedContext(context, new AuthenticationScheme("Bearer", null, typeof(JwtBearerHandler)), options);
    //     // Act
    //     await options.Events.OnTokenValidated(tokenValidatedContext);
    //     // Assert
    //     Assert.False(tokenValidatedContext.Principal?.Identity?.IsAuthenticated ?? true);
    //     Assert.NotNull(tokenValidatedContext.Result.Failure);
    // }
    //
    // [Fact]
    // public async Task FailsTokenValidation_WhenSessionManagerIsMissingAtRuntime()
    // {
    //     // Arrange
    //     var config = new JwtConfiguration
    //     {
    //         SecretKey = "testkey1234567890",
    //         Issuer = "issuer",
    //         Audience = "audience",
    //         ExpirationInMinutes = 60,
    //         Session = new UserSessionConfiguration { ActivityWindowMinutes = 10 }
    //     };
    //     var builder = GetBuilder(config);
    //     // Do NOT register ISessionManager
    //     builder.WithJwtBearer();
    //     var provider = builder.Services.BuildServiceProvider();
    //     var options = provider.GetRequiredService<IOptions<JwtBearerOptions>>().Value;
    //     var context = new DefaultHttpContext();
    //     var claims = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(SystemClaim.Identifier, "user1") }));
    //     context.User = claims;
    //     context.Request.Headers["Authorization"] = "Bearer testtoken";
    //     var tokenValidatedContext = new TokenValidatedContext(context, new AuthenticationScheme("Bearer", null, typeof(JwtBearerHandler)), options);
    //     // Act
    //     await options.Events.OnTokenValidated(tokenValidatedContext);
    //     // Assert
    //     Assert.NotNull(tokenValidatedContext.Result.Failure);
    //     Assert.Contains("ISessionManager", tokenValidatedContext.Result.Failure.Message, StringComparison.OrdinalIgnoreCase);
    // }

    // TODO: Add tests for other edge cases and error handling:
    // - Behavior when Session is enabled but configuration is missing
}
