using Api.Authentication;
using Api.Authentication.Jwt;
using Api.Authentication.Jwt.DependencyInjection;
using Api.Authentication.Jwt.Models;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Authenticated User Bearer Token",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT"
    });
    
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            []
        }
    });
    
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "SampleApiWithJwt", Version = "v1" });
});

builder.Services
    .AddApiAuthentication(builder.Configuration)
    .WithJwtBearer();

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

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
.WithName("GetBearerToken");

app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.RequireAuthorization()
.WithName("GetWeatherForecast");

app.Run();

UserProfile AuthenticateUser()
{
    return new UserProfile("Web", "STF12345", ["Admin", "User"]);
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