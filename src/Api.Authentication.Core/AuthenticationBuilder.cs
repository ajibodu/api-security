using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Api.Authentication.Core;

/// <summary>
/// Provides a builder for configuring authentication services and options.
/// </summary>
public class AuthenticationBuilder(IServiceCollection services, IConfiguration configuration)
{
    /// <summary>
    /// Gets the configuration instance used for authentication.
    /// </summary>
    public IConfiguration Configuration { get; } = configuration;
    /// <summary>
    /// Gets the service collection for registering authentication services.
    /// </summary>
    public readonly IServiceCollection Services = services;
}