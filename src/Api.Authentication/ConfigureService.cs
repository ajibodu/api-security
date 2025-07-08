using System.Reflection;
using System.Text;
using Api.Authentication.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Api.Authentication;

public static class ConfigureService
{
    /// <summary>
    /// Requires AddHttpContextAccessor 
    /// </summary>
    /// <param name="services"></param>
    public static AuthenticationBuilder AddApiAuthentication(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        return new AuthenticationBuilder(services);
    }
}

