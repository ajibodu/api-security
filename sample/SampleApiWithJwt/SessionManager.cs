using Api.Authentication.Core;

namespace SampleApiWithJwt;

public class SessionManager : ISessionManager
{
    public Task SetAsync(string identifier, string token, int activityWindowMinute)
    {
        throw new NotImplementedException();
    }

    public Task<bool> TryGetValue(string identifier, out string? token)
    {
        throw new NotImplementedException();
    }

    public Task UpdateActivityAsync(string identifier, int activityWindowMinute)
    {
        throw new NotImplementedException();
    }

    public Task RemoveAsync(string identifier)
    {
        throw new NotImplementedException();
    }
}