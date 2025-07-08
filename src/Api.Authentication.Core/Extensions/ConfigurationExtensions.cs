using Microsoft.Extensions.Configuration;

namespace Api.Authentication.Core.Extensions;

public static class ConfigurationExtensions
{
    public static T GetRequiredSection<T>(this IConfiguration configuration, string sectionName)
        where T : class
    {
        var section = configuration.GetRequiredSection(sectionName);
        var config = section.Get<T>();

        if (config is null)
            throw new InvalidOperationException($"Failed to bind section '{sectionName}' to type '{typeof(T).Name}'.");

        return config;
    }
}