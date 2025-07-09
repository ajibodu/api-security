namespace Api.Security.Authentication.Jwt.Models;

public record TokenResponse(string Jwt, int ExpirationInMinutes);