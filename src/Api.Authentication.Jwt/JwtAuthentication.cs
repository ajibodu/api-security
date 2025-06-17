using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Api.Authentication.Core;
using Api.Authentication.Jwt.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Api.Authentication.Jwt;

public static class JwtAuthentication
{
    public static void WithJwt(this AuthenticationBuilder builder, AuthReWriteConfig? reWriteConfig = null)
    {
        var jwtConfiguration = builder.Configuration.GetSection("JwtConfiguration").Get<Configuration>();
        builder.Services.Configure<Configuration>(builder.Configuration.GetSection("JwtConfiguration"));
        
        builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        if(jwtConfiguration?.Session != null)
            builder.Services.FindAndRegisterServices<ISessionManager>();
        
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtConfiguration!.Issuer,
                ValidAudience = jwtConfiguration.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.SecretKey))
                //ClockSkew = TimeSpan.Zero // Optional: Adjust this to allow for some clock skew between client and server
            };

            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = HandleTokenValidated(jwtConfiguration),
                OnMessageReceived = HandleMessageReceived(reWriteConfig)
            };
        });
    }
    
    private static Func<TokenValidatedContext, Task> HandleTokenValidated(Configuration configuration)
    {
        return async context =>
        {
            if (configuration.Session != null)
            {
                var sessionManager = context.HttpContext.RequestServices.GetRequiredService<ISessionManager>();
                var userId = context.Principal?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                var token = context.HttpContext.Request.Headers.Authorization.FirstOrDefault()?.Split(" ").Last(); 
                
                if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
                {
                    context.Fail("Invalid token claims");
                    return;
                }
                        
                if (!await sessionManager.TryGetValue(userId, out var activeToken))
                {
                    context.Fail("Token is no longer valid");
                    return;
                }
                
                if (activeToken != token)
                {
                    context.Fail("Token is no longer valid");
                    return;
                }

                await sessionManager.UpdateActivityAsync(userId, configuration.Session.ActivityWindowMinutes);
            }
        };
    }
    
    private static Func<MessageReceivedContext, Task> HandleMessageReceived(AuthReWriteConfig? reWriteConfig)
    {
        return context =>
        {
            // If the request is for hub...
            var currentPath = context.HttpContext.Request.Path;
            if (reWriteConfig?.PathStrings != null && reWriteConfig.PathStrings.Any(path => currentPath.StartsWithSegments(path, StringComparison.OrdinalIgnoreCase)))
            {
                if (reWriteConfig.Token != null)
                {
                    var accessToken = ExtractFromContext(context, reWriteConfig.Token.From, reWriteConfig.Token.Key);
                    if (!string.IsNullOrWhiteSpace(accessToken))
                        context.Token = accessToken;
                }

                foreach (var header in reWriteConfig.Headers)
                {
                    var value = ExtractFromContext(context, header.Value.From, header.Value.Key);
                    if (!string.IsNullOrWhiteSpace(value))
                        context.HttpContext.Request.Headers.TryAdd(header.Key, value);
                }
            }
            return Task.CompletedTask;
        };
    }
    
    private static string? ExtractFromContext(MessageReceivedContext context, Source source, string key)
    {
        return source switch
        {
            Source.Header => context.Request.Headers[key],
            Source.Query => context.Request.Query[key],
            Source.Cookie => context.Request.Cookies[key],
            _ => null
        };
    }
}