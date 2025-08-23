using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Api.Security.Authentication;
using Api.Security.Authentication.Jwt.Configurations;
using Api.Security.Authentication.Jwt.DependencyInjection;
using Api.Security.Authentication.Scheme.DependencyInjection;
using Api.Security.Authentication.Scheme.Models;
using Microsoft.AspNetCore.Authorization;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace MultipleAuthenticationTest;

public class MultipleAuthenticationSchemesTest
{
    private const string JwtSecret = "this-is-a-super-secure-secret-key-that-is-at-least-256-bits-long";
    private const string ValidApiKey = "test-api-key-123";
    private const string ValidUser = "admin";
    private const string ValidPassword = "password123";

    [Fact]
    public async Task Should_Support_Multiple_Authentication_Schemes()
    {
        // Arrange
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services
                        .AddApiAuthentication()
                        .WithJwtBearer(new JwtConfiguration
                        {
                            SecretKey = JwtSecret,
                            Issuer = "test-issuer",
                            Audience = "test-audience",
                            ExpirationInMinutes = 60
                        })
                        .WithBasicScheme(async (username, password) =>
                        {
                            bool isValid = username == ValidUser && password == ValidPassword;
                            return new AuthResponse(isValid);
                        }, "Basic")
                        .WithKeyScheme("X-API-Key", async (key) =>
                        {
                            bool isValid = key == ValidApiKey;
                            return new AuthResponse(isValid);
                        }, "ApiKey");

                    services.AddAuthorization();
                });

                webHost.Configure(app =>
                {
                    app.UseAuthentication();
                    app.UseAuthorization();

                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/jwt-only", async context =>
                        {
                            await context.Response.WriteAsync("JWT access granted");
                        }).RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "Bearer" });

                        endpoints.MapGet("/basic-only", async context =>
                        {
                            await context.Response.WriteAsync("Basic access granted");
                        }).RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "Basic" });

                        endpoints.MapGet("/api-key-only", async context =>
                        {
                            await context.Response.WriteAsync("API Key access granted");
                        }).RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "ApiKey" });

                        endpoints.MapGet("/multiple-schemes", async context =>
                        {
                            await context.Response.WriteAsync("Multiple schemes access granted");
                        }).RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "Bearer,Basic,ApiKey" });
                    });
                });
            });

        using var host = await hostBuilder.StartAsync();
        var client = host.GetTestClient();

        // Test JWT authentication
        var jwtToken = GenerateJwtToken();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);

        var jwtResponse = await client.GetAsync("/jwt-only");
        Assert.Equal(System.Net.HttpStatusCode.OK, jwtResponse.StatusCode);
        var jwtContent = await jwtResponse.Content.ReadAsStringAsync();
        Assert.Equal("JWT access granted", jwtContent);

        // Clear headers for next test
        client.DefaultRequestHeaders.Clear();

        // Test Basic authentication
        var basicAuthValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ValidUser}:{ValidPassword}"));
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", basicAuthValue);

        var basicResponse = await client.GetAsync("/basic-only");
        Assert.Equal(System.Net.HttpStatusCode.OK, basicResponse.StatusCode);
        var basicContent = await basicResponse.Content.ReadAsStringAsync();
        Assert.Equal("Basic access granted", basicContent);

        // Clear headers for next test
        client.DefaultRequestHeaders.Clear();

        // Test API Key authentication
        client.DefaultRequestHeaders.Add("X-API-Key", ValidApiKey);

        var apiKeyResponse = await client.GetAsync("/api-key-only");
        Assert.Equal(System.Net.HttpStatusCode.OK, apiKeyResponse.StatusCode);
        var apiKeyContent = await apiKeyResponse.Content.ReadAsStringAsync();
        Assert.Equal("API Key access granted", apiKeyContent);

        // Test multiple schemes endpoint with API Key
        var multipleResponse = await client.GetAsync("/multiple-schemes");
        Assert.Equal(System.Net.HttpStatusCode.OK, multipleResponse.StatusCode);
        var multipleContent = await multipleResponse.Content.ReadAsStringAsync();
        Assert.Equal("Multiple schemes access granted", multipleContent);
    }

    private string GenerateJwtToken()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(JwtSecret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, "testuser"),
                new Claim(ClaimTypes.NameIdentifier, "123")
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = "test-issuer",
            Audience = "test-audience",
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}