using System.Linq;
using Api.Security.Authentication.Scheme.Configurations;
using Api.Security.Authentication.Scheme.Handlers;
using Api.Security.Authentication.Scheme.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using AuthenticationBuilder = Api.Security.Authentication.Core.AuthenticationBuilder;

namespace Api.Security.Authentication.Scheme.DependencyInjection;

public static class AuthenticationBuilderExtensions
{
    public static AuthenticationBuilder WithBasicScheme(this AuthenticationBuilder builder, BasicConfiguration configuration, string schemeName = "Basic")
    {
        return builder.WithBasicScheme((userName, password) => Task.FromResult(new AuthResponse(userName == configuration.UserName && password == configuration.Password)), schemeName);
    }
    
    public static AuthenticationBuilder WithBasicScheme<TBasicAuthService>(this AuthenticationBuilder builder, string schemeName = "Basic") where TBasicAuthService : class, IBasicAuthenticationService
    {
        builder.Services.AddScoped<IBasicAuthenticationService, TBasicAuthService>();
        
        // Only register if not already registered by another authentication scheme
        if (!builder.Services.Any(s => s.ServiceType == typeof(ICurrentUser) && s.ImplementationType?.Namespace == "Api.Security.Authentication.Scheme"))
            builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        builder.Services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(schemeName, null);
        return builder;
    }
    
    public static AuthenticationBuilder WithBasicScheme(this AuthenticationBuilder builder, Func<string, string, Task<AuthResponse>> authenticateFunc, string schemeName = "Basic")
    {
        builder.Services.AddSingleton<IBasicAuthenticationService>(new DelegateBasicAuthenticationService(authenticateFunc));
        
        // Only register if not already registered by another authentication scheme
        if (!builder.Services.Any(s => s.ServiceType == typeof(ICurrentUser) && s.ImplementationType?.Namespace == "Api.Security.Authentication.Scheme"))
            builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        builder.Services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(schemeName, null);
        return builder;
    }
    
    public static AuthenticationBuilder WithKeyScheme(this AuthenticationBuilder builder, SimpleKeyConfiguration configuration, string schemeName = "ApiKey")
    {
        return builder.WithKeyScheme(configuration.HeaderName, (headerValue) => Task.FromResult(new AuthResponse(headerValue == configuration.HeaderValue)), schemeName);
    }
    
    public static AuthenticationBuilder WithKeyScheme<TKeyAuthService>(this AuthenticationBuilder builder, string headerName, string schemeName = "ApiKey") where TKeyAuthService : class, IKeyAuthenticationService
    {
        builder.Services.AddScoped<IKeyAuthenticationService, TKeyAuthService>();
        
        // Only register if not already registered by another authentication scheme
        if (!builder.Services.Any(s => s.ServiceType == typeof(ICurrentUser) && s.ImplementationType?.Namespace == "Api.Security.Authentication.Scheme"))
            builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        builder.Services.AddAuthentication()
            .AddScheme<KeyConfiguration, KeyAuthenticationHandler>(schemeName, null, options => options.HeaderName = headerName);
        return builder;
    }
    
    public static AuthenticationBuilder WithKeyScheme(this AuthenticationBuilder builder, string headerName, Func<string, Task<AuthResponse>> authenticateFunc, string schemeName = "ApiKey")
    {
        builder.Services.AddSingleton<IKeyAuthenticationService>(new DelegateKeyAuthenticationService(authenticateFunc));
        
        // Only register if not already registered by another authentication scheme
        if (!builder.Services.Any(s => s.ServiceType == typeof(ICurrentUser) && s.ImplementationType?.Namespace == "Api.Security.Authentication.Scheme"))
            builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        builder.Services.AddAuthentication()
            .AddScheme<KeyConfiguration, KeyAuthenticationHandler>(schemeName, null, options => options.HeaderName = headerName);
        return builder;
    }
}