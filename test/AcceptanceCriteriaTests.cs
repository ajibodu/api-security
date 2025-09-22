using Microsoft.Extensions.DependencyInjection;
using Api.Security.Authentication;
using Api.Security.Authentication.Jwt.Configurations;
using Api.Security.Authentication.Jwt.DependencyInjection;
using Api.Security.Authentication.Scheme.DependencyInjection;
using Api.Security.Authentication.Scheme.Models;

namespace Api.Security.Authentication.Test
{
    /// <summary>
    /// Tests to verify the acceptance criteria from the problem statement:
    /// "The user should be able to add multiple auth method such .WithJwtBearer.WithWithBasicScheme 
    /// with any combination as desired and this should work seamlessly in the api"
    /// </summary>
    public class AcceptanceCriteriaTests
    {
        [Fact]
        public void Should_Support_WithJwtBearer_WithBasicScheme_Combination()
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

            // Act - Test the exact combination mentioned in acceptance criteria
            var builder = services
                .AddApiAuthentication()
                .WithJwtBearer(jwtConfig)
                .WithBasicScheme(async (username, password) =>
                {
                    return new AuthResponse(username == "admin" && password == "password123");
                });

            // Assert
            Assert.NotNull(builder);
            Assert.IsType<Core.AuthenticationBuilder>(builder);
            
            // Verify services were registered
            var serviceProvider = services.BuildServiceProvider();
            Assert.True(services.Any(s => s.ServiceType.Name.Contains("Authentication")));
        }

        [Fact]
        public void Should_Support_All_Three_Authentication_Methods_In_Any_Order()
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

            // Act - Test different ordering combinations
            var builder1 = new ServiceCollection()
                .AddApiAuthentication()
                .WithJwtBearer(jwtConfig)
                .WithBasicScheme(async (u, p) => new AuthResponse(true))
                .WithKeyScheme("X-API-Key", async (k) => new AuthResponse(true));

            var builder2 = new ServiceCollection()
                .AddApiAuthentication()
                .WithBasicScheme(async (u, p) => new AuthResponse(true))
                .WithKeyScheme("X-API-Key", async (k) => new AuthResponse(true))
                .WithJwtBearer(jwtConfig);

            var builder3 = new ServiceCollection()
                .AddApiAuthentication()
                .WithKeyScheme("X-API-Key", async (k) => new AuthResponse(true))
                .WithJwtBearer(jwtConfig)
                .WithBasicScheme(async (u, p) => new AuthResponse(true));

            // Assert - All orderings should work
            Assert.NotNull(builder1);
            Assert.NotNull(builder2);
            Assert.NotNull(builder3);
        }

        [Fact]
        public void Should_Support_Any_Combination_As_Desired()
        {
            // Arrange & Act - Test various combinations as mentioned in requirements

            // Just JWT + Basic
            var combo1 = new ServiceCollection()
                .AddApiAuthentication()
                .WithJwtBearer(new JwtConfiguration
                {
                    SecretKey = "this-is-a-super-secure-secret-key-that-is-at-least-256-bits-long",
                    Issuer = "test", Audience = "test", ExpirationInMinutes = 60
                })
                .WithBasicScheme(async (u, p) => new AuthResponse(true));

            // Just Basic + Key
            var combo2 = new ServiceCollection()
                .AddApiAuthentication()
                .WithBasicScheme(async (u, p) => new AuthResponse(true))
                .WithKeyScheme("X-API-Key", async (k) => new AuthResponse(true));

            // Just JWT + Key
            var combo3 = new ServiceCollection()
                .AddApiAuthentication()
                .WithJwtBearer(new JwtConfiguration
                {
                    SecretKey = "this-is-a-super-secure-secret-key-that-is-at-least-256-bits-long",
                    Issuer = "test", Audience = "test", ExpirationInMinutes = 60
                })
                .WithKeyScheme("Authorization", async (k) => new AuthResponse(true));

            // Just single method (should still work)
            var combo4 = new ServiceCollection()
                .AddApiAuthentication()
                .WithBasicScheme(async (u, p) => new AuthResponse(true));

            // Assert - All combinations should work seamlessly
            Assert.NotNull(combo1);
            Assert.NotNull(combo2);
            Assert.NotNull(combo3);
            Assert.NotNull(combo4);
            
            // Verify each returns the proper type for potential further chaining
            Assert.IsType<Core.AuthenticationBuilder>(combo1);
            Assert.IsType<Core.AuthenticationBuilder>(combo2);
            Assert.IsType<Core.AuthenticationBuilder>(combo3);
            Assert.IsType<Core.AuthenticationBuilder>(combo4);
        }

        [Fact]
        public void Should_Work_Seamlessly_Without_Throwing_Exceptions()
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

            // Act & Assert - Should not throw any exceptions during configuration
            var exception = Record.Exception(() =>
            {
                services
                    .AddApiAuthentication()
                    .WithJwtBearer(jwtConfig)
                    .WithBasicScheme(async (username, password) =>
                    {
                        return new AuthResponse(username == "admin" && password == "password123");
                    })
                    .WithKeyScheme("X-API-Key", async (key) =>
                    {
                        return new AuthResponse(key == "valid-api-key");
                    });
                    
                // Try to build the service provider to ensure no registration conflicts
                var serviceProvider = services.BuildServiceProvider();
            });

            Assert.Null(exception);
        }
    }
}