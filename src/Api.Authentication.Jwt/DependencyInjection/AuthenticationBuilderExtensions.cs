using System.Text;
using Api.Authentication.Core;
using Api.Authentication.Core.DependencyInjection;
using Api.Authentication.Jwt.Configurations;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Api.Authentication.Jwt.DependencyInjection;

public static class AuthenticationBuilderExtensions
{
    public static void WithJwtBearer(this AuthenticationBuilder builder, Action<JwtConfiguration> configureOptions, AuthReWriteConfig? reWriteConfig = null)
    {
        var jwtConfiguration = new JwtConfiguration
        {
            SecretKey = string.Empty,
            Issuer = string.Empty,
            Audience = string.Empty
        };

        configureOptions(jwtConfiguration);
    
        ValidateAndConfigureJwt(builder, jwtConfiguration, reWriteConfig);
    }

    public static void WithJwtBearer(this AuthenticationBuilder builder, JwtConfiguration jwtConfiguration, AuthReWriteConfig? reWriteConfig = null)
    {
        builder.Services.Configure<JwtConfiguration>(options => 
        {
            options.SecretKey = jwtConfiguration.SecretKey;
            options.Issuer = jwtConfiguration.Issuer;
            options.Audience = jwtConfiguration.Audience;
            options.ExpirationInMinutes = jwtConfiguration.ExpirationInMinutes;
            options.Session = jwtConfiguration.Session;
        });

        ValidateAndConfigureJwt(builder, jwtConfiguration, reWriteConfig);
    }

    private static void ValidateAndConfigureJwt(AuthenticationBuilder builder, JwtConfiguration jwtConfiguration, AuthReWriteConfig? reWriteConfig)
    {
        if (jwtConfiguration is null)
            throw new ArgumentException(nameof(JwtConfiguration));
        jwtConfiguration.EnsureIsValid();
        
        builder.Services.AddScoped<IClaimResolver, ClaimResolver>();
        builder.Services.AddScoped<ICurrentUser, CurrentUser>();
        
        if(jwtConfiguration.Session != null)
            builder.Services.FindAndRegisterServices<ISessionManager>();
        
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            // Disable automatic claim type conversion (so claim name remains as was initially set)
            //options.MapInboundClaims = false;
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

    private static Func<TokenValidatedContext, Task> HandleTokenValidated(JwtConfiguration jwtConfiguration)
    {
        return async context =>
        {
            if (jwtConfiguration.Session != null)
            {
                var sessionManager = context.HttpContext.RequestServices.GetRequiredService<ISessionManager>();
                var userId = context.Principal?.FindFirst(SystemClaim.Identifier)?.Value;
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

                await sessionManager.UpdateActivityAsync(userId, jwtConfiguration.Session.ActivityWindowMinutes);
            }
        };
    }
    
    private static Func<MessageReceivedContext, Task> HandleMessageReceived(AuthReWriteConfig? reWriteConfig)
    {
        return context =>
        {
            // If the request is for signalR/websocket...
            var currentPath = context.HttpContext.Request.Path;
            if (reWriteConfig?.PathStrings != null && reWriteConfig.PathStrings.Any(path => currentPath.StartsWithSegments(path, StringComparison.OrdinalIgnoreCase)))
            {
                var tokenProvided = reWriteConfig.Token != null;
                var headersProvided = reWriteConfig.Headers is { Count: > 0 };
            
                if (!tokenProvided && !headersProvided)
                {
                    context.Fail("Either a token or at least one header must be provided in the rewrite configuration.");
                    return Task.CompletedTask;
                }
            
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