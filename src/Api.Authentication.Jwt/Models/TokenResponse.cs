namespace Api.Authentication.Jwt.Models;

public record TokenResponse(string Jwt, int ExpirationInMinutes);