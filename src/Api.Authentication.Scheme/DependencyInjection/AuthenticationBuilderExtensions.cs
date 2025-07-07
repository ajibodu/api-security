using Api.Authentication.Scheme.Configurations;
using Api.Authentication.Scheme.Handlers;
using Api.Authentication.Scheme.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using AuthenticationBuilder = Api.Authentication.Core.AuthenticationBuilder;

namespace Api.Authentication.Scheme.DependencyInjection;

public static class AuthenticationBuilderExtensions
{
    public static void WithBasicScheme(this AuthenticationBuilder builder, BasicConfiguration configuration, string schemeName = "Basic")
    {
        builder.WithBasicScheme((userName, password) => Task.FromResult(new AuthResponse(userName == configuration.UserName && password == configuration.Password)), schemeName);
    }
    
    public static void WithBasicScheme<TBasicAuthService>(this AuthenticationBuilder builder, string schemeName = "Basic") where TBasicAuthService : class, IBasicAuthenticationService
    {
        builder.Services.AddScoped<IBasicAuthenticationService, TBasicAuthService>();
        builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        builder.Services.AddAuthentication(schemeName)
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(schemeName, null);
    }
    
    public static void WithBasicScheme(this AuthenticationBuilder builder, Func<string, string, Task<AuthResponse>> authenticateFunc, string schemeName = "Basic")
    {
        builder.Services.AddSingleton<IBasicAuthenticationService>(new DelegateBasicAuthenticationService(authenticateFunc));
        builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        builder.Services.AddAuthentication(schemeName)
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(schemeName, null);
    }
    
    public static void WithKeyScheme(this AuthenticationBuilder builder, SimpleKeyConfiguration configuration, string schemeName = "Basic")
    {
        builder.WithKeyScheme(configuration.HeaderName, (headerValue) => Task.FromResult(new AuthResponse(headerValue == configuration.HeaderValue)), schemeName);
    }
    
    public static void WithKeyScheme<TKeyAuthService>(this AuthenticationBuilder builder, string headerName, string schemeName = "Basic") where TKeyAuthService : class, IKeyAuthenticationService
    {
        builder.Services.AddScoped<IKeyAuthenticationService, TKeyAuthService>();
        builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        builder.Services.AddAuthentication(schemeName)
            .AddScheme<KeyConfiguration, KeyAuthenticationHandler>(schemeName, null, options => options.HeaderName = headerName);
    }
    
    public static void WithKeyScheme(this AuthenticationBuilder builder, string headerName, Func<string, Task<AuthResponse>> authenticateFunc, string schemeName = "Basic")
    {
        builder.Services.AddSingleton<IKeyAuthenticationService>(new DelegateKeyAuthenticationService(authenticateFunc));
        builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        builder.Services.AddAuthentication(schemeName)
            .AddScheme<KeyConfiguration, KeyAuthenticationHandler>(schemeName, null, options => options.HeaderName = headerName);
    }
}