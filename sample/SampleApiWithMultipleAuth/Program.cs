using Api.Security.Authentication;
using Api.Security.Authentication.Core.Extensions;
using Api.Security.Authentication.Jwt;
using Api.Security.Authentication.Jwt.Configurations;
using Api.Security.Authentication.Jwt.DependencyInjection;
using Api.Security.Authentication.Jwt.Models;
using Api.Security.Authentication.Scheme.DependencyInjection;
using Api.Security.Authentication.Scheme.Models;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using SampleApiWithMultipleAuth;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // JWT Bearer token definition
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Bearer Token",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT"
    });

    // Basic authentication definition
    c.AddSecurityDefinition("Basic", new OpenApiSecurityScheme
    {
        Description = "Basic Authentication",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Basic"
    });

    // API Key definition
    c.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Description = "API Key Authentication",
        Name = "X-API-Key",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Multiple Authentication Schemes API", Version = "v1" });
});

// Configure multiple authentication schemes
builder.Services
    .AddApiAuthentication()
    .WithJwtBearer(builder.Configuration.GetRequiredSection<JwtConfiguration>(nameof(JwtConfiguration)))
    .WithBasicScheme(async (username, password) => {
        // Simple demo authentication - in real apps, validate against database
        bool isValid = username == "admin" && password == "password123";
        return new AuthResponse(isValid);
    }, "Basic")
    .WithKeyScheme("X-API-Key", async (key) => {
        // Simple demo API key validation - in real apps, validate against database
        bool isValid = key == "demo-api-key-12345";
        return new AuthResponse(isValid);
    }, "ApiKey");

builder.Services.AddScoped<CurrentUserProperties>();
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Multiple Auth API V1");
        c.DefaultModelsExpandDepth(-1); // Hide models in swagger UI
    });
}

app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

// Endpoint to generate JWT tokens
app.MapGet("/token", async (ICurrentUser currentUser) =>
{
    var userProfile = AuthenticateUser();
    
    var claimsInfo = new List<CustomClaim>
    {
        new(UserClaim.AuthChannel, userProfile.AuthChannel),
        new(UserClaim.StaffId, userProfile.StaffId, IsUniqueId: true),
        new(UserClaim.Role, JsonConvert.SerializeObject(userProfile.Roles), CustomClaimValueTypes.JsonArray),
    };

    return await currentUser.GenerateJwt(claimsInfo);
})
.WithName("GetBearerToken")
.WithOpenApi();

// JWT-only endpoint
app.MapGet("/jwt-only", (CurrentUserProperties currentUser) =>
{
    return new { 
        message = "JWT authentication successful",
        user = currentUser.StaffId,
        authMethod = "JWT Bearer" 
    };
})
.RequireAuthorizationWithScheme("Bearer")
.WithName("JwtOnlyEndpoint")
.WithOpenApi();

// Basic authentication only endpoint
app.MapGet("/basic-only", () =>
{
    return new { 
        message = "Basic authentication successful",
        authMethod = "Basic" 
    };
})
.RequireAuthorizationWithScheme("Basic")
.WithName("BasicOnlyEndpoint")
.WithOpenApi();

// API Key only endpoint
app.MapGet("/api-key-only", () =>
{
    return new { 
        message = "API Key authentication successful",
        authMethod = "API Key" 
    };
})
.RequireAuthorizationWithScheme("ApiKey")
.WithName("ApiKeyOnlyEndpoint")
.WithOpenApi();

// Multiple authentication schemes endpoint (accepts any)
app.MapGet("/multi-auth", (HttpContext context) =>
{
    var authScheme = context.User?.Identity?.AuthenticationType ?? "Unknown";
    
    return new { 
        message = "Multi-authentication successful",
        authMethod = authScheme,
        claims = context.User?.Claims?.Select(c => new { c.Type, c.Value })?.ToArray() ?? Array.Empty<object>()
    };
})
.RequireAuthorization(policy => policy.RequireAuthenticatedUser())
.WithName("MultiAuthEndpoint")
.WithOpenApi();

// Weather forecast (accepts any authentication method)
app.MapGet("/weatherforecast", (HttpContext context) =>
{
    var authScheme = context.User?.Identity?.AuthenticationType ?? "Unknown";
    
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
        
    return new {
        authMethod = authScheme,
        forecast = forecast
    };
})
.RequireAuthorization()
.WithName("GetWeatherForecast")
.WithOpenApi();

app.Run();

UserProfile AuthenticateUser()
{
    return new UserProfile("MultipleAuth", "DEMO12345", ["Admin", "User"]);
}

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

public static class UserClaim
{
    public const string AuthChannel = "auth_channel";
    public const string StaffId = "staff_id";
    public const string Role = "role";
}

public record UserProfile(string AuthChannel, string StaffId, string[] Roles);