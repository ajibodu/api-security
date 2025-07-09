using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Api.Security.Authentication.Core;

/// <summary>
/// Provides a builder for configuring authentication services and options.
/// </summary>
public class AuthenticationBuilder(IServiceCollection services)
{
    /// <summary>
    /// Gets the service collection for registering authentication services.
    /// </summary>
    public readonly IServiceCollection Services = services;
}