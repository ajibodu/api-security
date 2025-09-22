using Microsoft.Extensions.DependencyInjection;
using Api.Security.Authentication;
using Api.Security.Authentication.Jwt.Configurations;
using Api.Security.Authentication.Jwt.DependencyInjection;
using Api.Security.Authentication.Scheme.DependencyInjection;
using Api.Security.Authentication.Scheme.Models;
using Xunit;

namespace Api.Security.Authentication.Test
{
    public class MultipleAuthenticationBuilderTests
    {
        [Fact]
        public void AddApiAuthentication_Should_Return_AuthenticationBuilder()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            var builder = services.AddApiAuthentication();

            // Assert
            Assert.NotNull(builder);
            Assert.IsType<Core.AuthenticationBuilder>(builder);
        }

        [Fact]
        public void WithJwtBearer_Should_Return_AuthenticationBuilder_For_Chaining()
        {
            // Arrange
            var services = new ServiceCollection();
            var jwtConfig = new JwtConfiguration
            {
                SecretKey = "this-is-a-super-secure-secret-key-that-is-at-least-256-bits-long",
                Issuer = "test-issuer",
                Audience = "test-audience",
                ExpirationInMinutes = 60
            };

            // Act
            var builder = services.AddApiAuthentication()
                .WithJwtBearer(jwtConfig);

            // Assert
            Assert.NotNull(builder);
            Assert.IsType<Core.AuthenticationBuilder>(builder);
        }

        [Fact]
        public void WithBasicScheme_Should_Return_AuthenticationBuilder_For_Chaining()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            var builder = services.AddApiAuthentication()
                .WithBasicScheme(async (username, password) => 
                {
                    bool isValid = username == "admin" && password == "password";
                    return new AuthResponse(isValid);
                }, "Basic");

            // Assert
            Assert.NotNull(builder);
            Assert.IsType<Core.AuthenticationBuilder>(builder);
        }

        [Fact]
        public void WithKeyScheme_Should_Return_AuthenticationBuilder_For_Chaining()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            var builder = services.AddApiAuthentication()
                .WithKeyScheme("X-API-Key", async (key) => 
                {
                    bool isValid = key == "valid-key";
                    return new AuthResponse(isValid);
                }, "ApiKey");

            // Assert
            Assert.NotNull(builder);
            Assert.IsType<Core.AuthenticationBuilder>(builder);
        }

        [Fact]
        public void Multiple_Authentication_Schemes_Should_Chain_Successfully()
        {
            // Arrange
            var services = new ServiceCollection();
            var jwtConfig = new JwtConfiguration
            {
                SecretKey = "this-is-a-super-secure-secret-key-that-is-at-least-256-bits-long",
                Issuer = "test-issuer",
                Audience = "test-audience",
                ExpirationInMinutes = 60
            };

            // Act & Assert - This should not throw any exceptions
            var builder = services.AddApiAuthentication()
                .WithJwtBearer(jwtConfig)
                .WithBasicScheme(async (username, password) => 
                {
                    bool isValid = username == "admin" && password == "password";
                    return new AuthResponse(isValid);
                }, "Basic")
                .WithKeyScheme("X-API-Key", async (key) => 
                {
                    bool isValid = key == "valid-key";
                    return new AuthResponse(isValid);
                }, "ApiKey");

            // Verify we can chain all three authentication methods
            Assert.NotNull(builder);
            Assert.IsType<Core.AuthenticationBuilder>(builder);

            // Verify services were registered
            var serviceProvider = services.BuildServiceProvider();
            
            // At minimum, there should be authentication services registered
            Assert.True(services.Any(s => s.ServiceType.Name.Contains("Authentication")));
        }
    }
}