namespace SampleApiWithMultipleAuth;

public static class AuthorizationEndpointConventionBuilderExtensions
{
    public static TBuilder RequireAuthorizationWithScheme<TBuilder>(
        this TBuilder builder,
        string scheme)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.RequireAuthorization(policy =>
        {
            policy.AddAuthenticationSchemes(scheme);
            policy.RequireAuthenticatedUser();
        });

        return builder;
    }
}