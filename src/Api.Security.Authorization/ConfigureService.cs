using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Api.Security.Authorization;

public static class ConfigureService
{
    /// <summary>
    /// Requires AddHttpContextAccessor 
    /// </summary>
    /// <param name="services"></param>
    /// <param name="claimPolicies"></param>
    /// <param name="rolePolicies"></param>
    public static void AddApiAuthorization(this IServiceCollection services, 
        Dictionary<string, ClaimPolicyConfig>? claimPolicies = null,
        Dictionary<string, string[]>? rolePolicies = null)
    {
        services.AddAuthorization(options =>
        {
            if (claimPolicies != null)
            {
                foreach (var policy in claimPolicies)
                {
                    options.AddPolicy(policy.Key, p => p.RequireClaim(policy.Value.ClaimType, policy.Value.RequiredValues));
                }
            }
            
            if (rolePolicies != null)
            {
                foreach (var policy in rolePolicies)
                {
                    options.AddPolicy(policy.Key, p => p.RequireRole(policy.Value));
                }
            }

        });
    }
}


