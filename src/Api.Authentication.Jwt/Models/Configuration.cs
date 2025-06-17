using Microsoft.AspNetCore.Http;

namespace Api.Authentication.Jwt.Models;

public class Configuration
{
    public required string SecretKey { get; set; }
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public int ExpirationInMinutes { get; set; }
    public IEnumerable<PathString>? Type { get; set; }
    public UserSessionConfiguration? Session { get; set; }
    
}

public class UserSessionConfiguration
{
    public int ActivityWindowMinutes { get; set; }
}