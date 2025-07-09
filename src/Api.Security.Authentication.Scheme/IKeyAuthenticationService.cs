using Api.Security.Authentication.Scheme.Models;

namespace Api.Security.Authentication.Scheme;

public interface IKeyAuthenticationService
{
    Task<AuthResponse> Authenticate(string key);
}