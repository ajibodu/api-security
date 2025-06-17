using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Api.Authentication.Core;

public class AuthenticationBuilder(IServiceCollection services, IConfiguration configuration)
{
    public IConfiguration Configuration { get; } = configuration;
    public readonly IServiceCollection Services = services;
}