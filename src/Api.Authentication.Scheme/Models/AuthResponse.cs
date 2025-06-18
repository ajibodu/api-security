namespace Api.Authentication.Scheme.Models;

public record AuthResponse(bool IsValid, Dictionary<string, string>? Claims = null);