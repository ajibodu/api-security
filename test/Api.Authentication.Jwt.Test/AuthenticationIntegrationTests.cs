using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Api.Authentication.Jwt.Configurations;
using Api.Authentication.Jwt.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Api.Authentication.Core; // For ISessionManager, SystemClaim
using Moq; // For mocking

namespace Api.Authentication.Jwt.Test;

public class AuthenticationIntegrationTests
{
    private static TestServer CreateServer(JwtConfiguration jwtConfig, Action<IServiceCollection>? configureServices = null)
    {
        var builder = new WebHostBuilder()
            .ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    {"JwtConfiguration:SecretKey", jwtConfig.SecretKey},
                    {"JwtConfiguration:Issuer", jwtConfig.Issuer},
                    {"JwtConfiguration:Audience", jwtConfig.Audience},
                    {"JwtConfiguration:ExpirationInMinutes", jwtConfig.ExpirationInMinutes.ToString()}
                });
            })
            .ConfigureServices(services =>
            {
                var configuration = new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        {"JwtConfiguration:SecretKey", jwtConfig.SecretKey},
                        {"JwtConfiguration:Issuer", jwtConfig.Issuer},
                        {"JwtConfiguration:Audience", jwtConfig.Audience},
                        {"JwtConfiguration:ExpirationInMinutes", jwtConfig.ExpirationInMinutes.ToString()}
                    })
                    .Build();
                var builder = new Api.Authentication.Core.AuthenticationBuilder(services, configuration);
                builder.WithJwtBearer();
                configureServices?.Invoke(services);
                services.AddControllers();
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/secure", context =>
                    {
                        if (context.User.Identity?.IsAuthenticated == true)
                            return context.Response.WriteAsync("Authenticated");
                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        return Task.CompletedTask;
                    });
                });
            });
        return new TestServer(builder);
    }

    private static string GenerateJwtToken(JwtConfiguration config, string userId)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.SecretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            issuer: config.Issuer,
            audience: config.Audience,
            claims: new[] { new System.Security.Claims.Claim(Api.Authentication.Core.SystemClaim.Identifier, userId) },
            expires: DateTime.UtcNow.AddMinutes(config.ExpirationInMinutes),
            signingCredentials: creds
        );
        return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
    }

    [Fact]
    public async Task ReturnsAuthenticated_ForValidJwt()
    {
        // Arrange
        var jwtConfig = new JwtConfiguration
        {
            SecretKey = "YourSuperSecretKeyShouldBeAtLeast32CharactersLong",
            Issuer = "issuer",
            Audience = "audience",
            ExpirationInMinutes = 60
        };
        using var server = CreateServer(jwtConfig);
        using var client = server.CreateClient();
        var token = GenerateJwtToken(jwtConfig, "user1");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, token);
        // Act
        var response = await client.GetAsync("/secure");
        var content = await response.Content.ReadAsStringAsync();
        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Authenticated", content as string);
    }

    [Fact]
    public async Task ReturnsUnauthorized_ForInvalidJwt()
    {
        // Arrange
        var jwtConfig = new JwtConfiguration
        {
            SecretKey = "YourSuperSecretKeyShouldBeAtLeast32CharactersLong",
            Issuer = "issuer",
            Audience = "audience",
            ExpirationInMinutes = 60
        };
        using var server = CreateServer(jwtConfig);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, "invalidtoken");
        // Act
        var response = await client.GetAsync("/secure");
        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    //[Fact]
    // public async Task ReturnsUnauthorized_WhenTokenIsExpired()
    // {
    //     // Arrange
    //     var jwtConfig = new JwtConfiguration
    //     {
    //         SecretKey = "YourSuperSecretKeyShouldBeAtLeast32CharactersLong",
    //         Issuer = "issuer",
    //         Audience = "audience",
    //         ExpirationInMinutes = -1 // Expired token
    //     };
    //     using var server = CreateServer(jwtConfig);
    //     using var client = server.CreateClient();
    //     var token = GenerateJwtToken(jwtConfig, "user1");
    //     client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, token);
    //     // Act
    //     var response = await client.GetAsync("/secure");
    //     // Assert
    //     Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    // }

    [Fact]
    public async Task ReturnsAuthenticated_WhenSessionManagerValidatesToken()
    {
        // Arrange
        var jwtConfig = new JwtConfiguration
        {
            SecretKey = "YourSuperSecretKeyShouldBeAtLeast32CharactersLong",
            Issuer = "issuer",
            Audience = "audience",
            ExpirationInMinutes = 60,
            Session = new UserSessionConfiguration { ActivityWindowMinutes = 10 }
        };
        var userId = "user1";
        var token = GenerateJwtToken(jwtConfig, userId);
        using var server = CreateServer(jwtConfig, services =>
        {
            var sessionManagerMock = new Mock<ISessionManager>();
            sessionManagerMock.Setup(m => m.TryGetValue(userId, out token)).ReturnsAsync(true);
            sessionManagerMock.Setup(m => m.UpdateActivityAsync(userId, 10)).Returns(Task.CompletedTask);
            services.AddSingleton(sessionManagerMock.Object);
        });
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, token);
        // Act
        var response = await client.GetAsync("/secure");
        var content = await response.Content.ReadAsStringAsync();
        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Authenticated", content as string);
    }

    // [Fact]
    // public async Task ReturnsUnauthorized_WhenSessionManagerRejectsToken()
    // {
    //     // Arrange
    //     var jwtConfig = new JwtConfiguration
    //     {
    //         SecretKey = "YourSuperSecretKeyShouldBeAtLeast32CharactersLong",
    //         Issuer = "issuer",
    //         Audience = "audience",
    //         ExpirationInMinutes = 60,
    //         Session = new UserSessionConfiguration { ActivityWindowMinutes = 10 }
    //     };
    //     var userId = "user1";
    //     var token = GenerateJwtToken(jwtConfig, userId);
    //     using var server = CreateServer(jwtConfig, services =>
    //     {
    //         var sessionManagerMock = new Mock<ISessionManager>();
    //         string? dummy = null;
    //         sessionManagerMock.Setup(m => m.TryGetValue(userId, out dummy)).ReturnsAsync(false);
    //         services.AddSingleton(sessionManagerMock.Object);
    //     });
    //     using var client = server.CreateClient();
    //     client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, token);
    //     // Act
    //     var response = await client.GetAsync("/secure");
    //     // Assert
    //     Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    // }

    [Fact]
    public async Task AcceptsTokenFromQueryString_WhenCustomRewriteConfigIsUsed()
    {
        // Arrange
        var jwtConfig = new JwtConfiguration
        {
            SecretKey = "YourSuperSecretKeyShouldBeAtLeast32CharactersLong",
            Issuer = "issuer",
            Audience = "audience",
            ExpirationInMinutes = 60
        };
        var token = GenerateJwtToken(jwtConfig, "user1");
        var rewriteConfig = new AuthReWriteConfig
        {
            PathStrings = ["/hub"],
            Token = new Mapping { From = Source.Query, Key = "access_token" },
            Headers = new Dictionary<string, Mapping>()
        };
        using var server = new TestServer(new WebHostBuilder()
            .ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    {"JwtConfiguration:SecretKey", jwtConfig.SecretKey},
                    {"JwtConfiguration:Issuer", jwtConfig.Issuer},
                    {"JwtConfiguration:Audience", jwtConfig.Audience},
                    {"JwtConfiguration:ExpirationInMinutes", jwtConfig.ExpirationInMinutes.ToString()}
                });
            })
            .ConfigureServices(services =>
            {
                var configuration = new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        {"JwtConfiguration:SecretKey", jwtConfig.SecretKey},
                        {"JwtConfiguration:Issuer", jwtConfig.Issuer},
                        {"JwtConfiguration:Audience", jwtConfig.Audience},
                        {"JwtConfiguration:ExpirationInMinutes", jwtConfig.ExpirationInMinutes.ToString()}
                    })
                    .Build();
                var builder = new Api.Authentication.Core.AuthenticationBuilder(services, configuration);
                builder.WithJwtBearer(rewriteConfig);
                services.AddControllers();
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/hub", context =>
                    {
                        if (context.User.Identity?.IsAuthenticated == true)
                            return context.Response.WriteAsync("Authenticated");
                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        return Task.CompletedTask;
                    });
                });
            }));
        using var client = server.CreateClient();
        // Act
        var response = await client.GetAsync($"/hub?access_token={token}");
        var content = await response.Content.ReadAsStringAsync();
        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Authenticated", content as string);
    }
}
