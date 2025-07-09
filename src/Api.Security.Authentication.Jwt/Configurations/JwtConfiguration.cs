using Microsoft.AspNetCore.Http;
using System.Diagnostics.CodeAnalysis;

namespace Api.Security.Authentication.Jwt.Configurations;

/// <summary>
/// Represents the configuration settings required for JWT authentication.
/// </summary>
public class JwtConfiguration
{
    /// <summary>
    /// The secret key used to sign JWT tokens.
    /// </summary>
    public required string SecretKey { get; set; }
    /// <summary>
    /// The issuer of the JWT tokens.
    /// </summary>
    public required string Issuer { get; set; }
    /// <summary>
    /// The audience for the JWT tokens.
    /// </summary>
    public required string Audience { get; set; }
    /// <summary>
    /// The expiration time (in minutes) for JWT tokens.
    /// </summary>
    public int ExpirationInMinutes { get; set; }
    /// <summary>
    /// Optional path types for the JWT configuration.
    /// </summary>
    public IEnumerable<PathString>? Type { get; set; }
    /// <summary>
    /// Optional user session configuration.
    /// </summary>
    public UserSessionConfiguration? Session { get; set; }

    /// <summary>
    /// Validates the configuration and throws if invalid.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown if any required property is missing or invalid.</exception>
    public void EnsureIsValid()
    {
        if (string.IsNullOrWhiteSpace(SecretKey))
            throw new ArgumentNullException(SecretKey);
        if (string.IsNullOrWhiteSpace(Issuer))
            throw new ArgumentNullException(Issuer);
        if (string.IsNullOrWhiteSpace(Audience))
            throw new ArgumentNullException(Audience);
        if (ExpirationInMinutes <= 0)
            throw new ArgumentException("ExpirationInMinutes must be greater than zero.");
    }
}

/// <summary>
/// Represents the user session configuration for JWT authentication.
/// </summary>
public class UserSessionConfiguration
{
    /// <summary>
    /// The activity window (in minutes) for user sessions.
    /// </summary>
    public int ActivityWindowMinutes { get; set; }
}