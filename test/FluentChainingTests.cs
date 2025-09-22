using Microsoft.Extensions.DependencyInjection;
using Api.Security.Authentication;
using Api.Security.Authentication.Jwt.Configurations;
using Api.Security.Authentication.Jwt.DependencyInjection;
using Api.Security.Authentication.Scheme.DependencyInjection;
using Api.Security.Authentication.Scheme.Models;

namespace Api.Security.Authentication.Test
{
    public class FluentChainingTests
    {
        [Fact]
        public void Should_Enable_Fluent_Chaining_With_All_Authentication_Types()
        {
            // Arrange
            var services = new ServiceCollection();
            var jwtConfig = new JwtConfiguration
            {
                SecretKey = "this-is-a-super-secure-secret-key-that-is-at-least-256-bits-long-for-testing-purposes",
                Issuer = "test-issuer",
                Audience = "test-audience",
                ExpirationInMinutes = 60
            };

            // Act - This should compile and execute without errors
            var result = services
                .AddApiAuthentication()
                .WithJwtBearer(jwtConfig)
                .WithBasicScheme(async (username, password) =>
                {
                    return new AuthResponse(username == "admin" && password == "password");
                }, "Basic")
                .WithKeyScheme("X-API-Key", async (key) =>
                {
                    return new AuthResponse(key == "valid-key");
                }, "ApiKey");

            // Assert
            Assert.NotNull(result);
            Assert.IsType<Core.AuthenticationBuilder>(result);
            
            // Verify the service collection has authentication services
            var serviceProvider = services.BuildServiceProvider();
            Assert.True(services.Count > 0);
        }

        [Fact]  
        public void Should_Allow_Partial_Chaining()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act - Should be able to chain just some authentication methods
            var result = services
                .AddApiAuthentication()
                .WithBasicScheme(async (username, password) =>
                {
                    return new AuthResponse(username == "test" && password == "pass");
                })
                .WithKeyScheme("Authorization", async (key) =>
                {
                    return new AuthResponse(key == "Bearer valid-token");
                });

            // Assert
            Assert.NotNull(result);
            Assert.IsType<Core.AuthenticationBuilder>(result);
        }
    }
}