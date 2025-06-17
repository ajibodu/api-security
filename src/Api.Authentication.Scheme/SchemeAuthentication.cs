using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using AuthenticationBuilder = Api.Authentication.Core.AuthenticationBuilder;

namespace Api.Authentication.Scheme;

public static class SchemeAuthentication
{
    public static void WithBasicScheme(this AuthenticationBuilder builder, IBasicConfiguration configuration, string schemeName = "Basic")
    {
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = schemeName;
            options.DefaultChallengeScheme = schemeName;
        });

        builder.Services.AddAuthentication()
            .AddScheme<BasicConfiguration, BasicAuthenticationHandler>(schemeName, "",options =>
            {
                options.UserName = configuration.UserName;
                options.Password = configuration.Password;
            });
    }
    
    public static void WithKeyScheme(this AuthenticationBuilder builder, ApiKeyConfiguration configuration, string schemeName = "Basic")
    {
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = schemeName;
            options.DefaultChallengeScheme = schemeName;
        });

        builder.Services.AddAuthentication()
            .AddScheme<ApiKeyConfiguration, ApiKeyAuthenticationHandler>(schemeName, options =>
            {
                options.ApiKeyHeaderName = configuration.ApiKeyHeaderName;
                options.ApiKeyHeaderValue = configuration.ApiKeyHeaderValue;
            });
    }
}