namespace Api.Security.Authentication.Core;

/// <summary>
/// Provides well-known claim types used throughout the authentication system.
/// </summary>
/// <remarks>
/// Consider making this class static as it only contains constants.
/// </remarks>
public class SystemClaim
{
    /// <summary>
    /// The claim type for JWT version.
    /// </summary>
    public const string JwtVersion = "ver"; 
    /// <summary>
    /// The claim type for unique identifier.
    /// </summary>
    public const string Identifier = "identifier"; 
}