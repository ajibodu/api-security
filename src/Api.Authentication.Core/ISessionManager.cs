namespace Api.Authentication.Core;

public interface ISessionManager
{
    public Task SetAsync(string identifier, string token, int activityWindowMinute);
    public Task<bool> TryGetValue(string identifier, out string? token);
    public Task UpdateActivityAsync(string identifier, int activityWindowMinute);
    Task RemoveAsync(string identifier);
}