using Api.Authentication.Scheme.Models;

namespace Api.Authentication.Scheme;

public interface IKeyAuthenticationService
{
    Task<AuthResponse> Authenticate(string key);
}