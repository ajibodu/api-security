namespace Api.Security.Authentication.Scheme.Models;

public record AuthResponse(bool IsValid, Dictionary<string, string>? Claims = null);