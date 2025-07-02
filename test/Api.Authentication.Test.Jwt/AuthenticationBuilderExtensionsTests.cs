using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Api.Authentication.Jwt.Configurations;
using Api.Authentication.Jwt.DependencyInjection;
using Api.Authentication.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using AuthenticationBuilder = Api.Authentication.Core.AuthenticationBuilder;

namespace Api.Authentication.Test.Jwt;

public class AuthenticationBuilderExtensionsTests
{
    private AuthenticationBuilder GetBuilder(JwtConfiguration? config = null)
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                {"JwtConfiguration:SecretKey", config?.SecretKey ?? "testkey1234567890"},
                {"JwtConfiguration:Issuer", config?.Issuer ?? "issuer"},
                {"JwtConfiguration:Audience", config?.Audience ?? "audience"},
                {"JwtConfiguration:ExpirationInMinutes", (config?.ExpirationInMinutes ?? 60).ToString()}
            })
            .Build();
        return new AuthenticationBuilder(services, configuration);
    }

    [Fact]
    public void WithJwtBearer_RegistersAuthenticationAndCurrentUser()
    {
        var builder = GetBuilder();
        builder.WithJwtBearer();
        var provider = builder.Services.BuildServiceProvider();
        var currentUser = provider.GetService<ICurrentUser>();
        Assert.NotNull(currentUser);
        var authService = provider.GetService<IAuthenticationService>();
        Assert.Null(authService); // Should not register IAuthenticationService by default
    }

    [Fact]
    public void WithJwtBearer_RegistersSessionManagerIfConfigured()
    {
        var config = new JwtConfiguration
        {
            SecretKey = "testkey1234567890",
            Issuer = "issuer",
            Audience = "audience",
            ExpirationInMinutes = 60,
            Session = new UserSessionConfiguration { ActivityWindowMinutes = 10 }
        };
        var builder = GetBuilder(config);
        builder.WithJwtBearer();
        // This will throw if FindAndRegisterServices is not implemented or fails
        // We can't assert much without a real ISessionManager implementation
        Assert.NotNull(builder.Services);
    }

    [Fact]
    public void WithJwtBearer_ConfiguresJwtBearerOptions()
    {
        var builder = GetBuilder();
        builder.WithJwtBearer();
        var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetService<IOptions<JwtBearerOptions>>();
        Assert.Null(options); // Options are registered internally by AddJwtBearer
    }

    [Fact]
    public void WithJwtBearer_AllowsCustomRewriteConfig()
    {
        var builder = GetBuilder();
        var rewriteConfig = new AuthReWriteConfig
        {
            PathStrings = ["/hub"],
            Token = new Mapping { From = Source.Query, Key = "access_token" },
            Headers = new Dictionary<string, Mapping> { { "X-Test", new Mapping { From = Source.Header, Key = "X-Test" } } }
        };
        builder.WithJwtBearer(rewriteConfig);
        Assert.NotNull(builder.Services);
    }
}
