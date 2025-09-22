namespace Api.Security.Authentication.Core;

/// <summary>
/// Defines contract for managing user sessions in a distributed or in-memory store.
/// </summary>
public interface ISessionManager
{
    /// <summary>
    /// Sets a session token for the specified identifier with an activity window.
    /// </summary>
    /// <param name="identifier">The unique session identifier.</param>
    /// <param name="token">The session token.</param>
    /// <param name="activityWindowMinute">The activity window in minutes.</param>
    Task SetAsync(string identifier, string token, int activityWindowMinute);

    /// <summary>
    /// Attempts to get a session token for the specified identifier.
    /// </summary>
    /// <param name="identifier">The unique session identifier.</param>
    /// <param name="token">The session token if found.</param>
    /// <returns>True if found; otherwise, false.</returns>
    /// <remarks>
    /// Consider returning a tuple (bool found, string? token) for async idiomatic usage.
    /// </remarks>
    Task<bool> TryGetValue(string identifier, out string token);

    /// <summary>
    /// Updates the activity window for the specified session identifier.
    /// </summary>
    /// <param name="identifier">The unique session identifier.</param>
    /// <param name="activityWindowMinute">The new activity window in minutes.</param>
    Task UpdateActivityAsync(string identifier, int activityWindowMinute);

    /// <summary>
    /// Removes the session for the specified identifier.
    /// </summary>
    /// <param name="identifier">The unique session identifier.</param>
    Task RemoveAsync(string identifier);
}