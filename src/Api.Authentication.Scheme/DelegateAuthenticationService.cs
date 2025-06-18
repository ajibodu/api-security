namespace Api.Authentication.Scheme;

public class DelegateBasicAuthenticationService(Func<string, string, Task<bool>> authenticateFunc) : IBasicAuthenticationService
{
    public Task<bool> Authenticate(string username, string password)
    {
        return authenticateFunc(username, password);
    }
}

public class DelegateKeyAuthenticationService(Func<string, Task<bool>> authenticateFunc) : IKeyAuthenticationService
{
    public Task<bool> Authenticate(string key)
    {
        return authenticateFunc(key);
    }
}