using System.Reflection;
using Microsoft.Extensions.DependencyInjection;

namespace Api.Authentication.Core;

public static class ServiceCollectionExtensions
{
    public static void FindAndRegisterServices<TInterface>(this IServiceCollection services, ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        ArgumentNullException.ThrowIfNull(services);
        
        var libraryAssembly = typeof(TInterface).Assembly;
        var assemblies = AppDomain.CurrentDomain.GetAssemblies()
            .Where(a => a.GetReferencedAssemblies().Any(r => r.FullName == libraryAssembly.FullName))
            .ToList();
        
        // Always include the entry assembly and executing assembly
        assemblies.Add(Assembly.GetEntryAssembly());
        assemblies.Add(Assembly.GetExecutingAssembly());
        
        // Remove duplicates
        assemblies = assemblies.Distinct().ToList();
        
        var interfaceType = typeof(TInterface);
        if (!interfaceType.IsInterface)
            throw new ArgumentException($"{nameof(TInterface)} must be an interface type");

        foreach (var assembly in assemblies)
        {
            var implementationTypes = assembly.GetTypes()
                .Where(t => t is { IsInterface: false, IsAbstract: false } && interfaceType.IsAssignableFrom(t));
        
            foreach (var implementationType in implementationTypes)
            {
                switch (lifetime)
                {
                    case ServiceLifetime.Singleton:
                        services.AddSingleton(interfaceType, implementationType);
                        break;
                    case ServiceLifetime.Scoped:
                        services.AddScoped(interfaceType, implementationType);
                        break;
                    case ServiceLifetime.Transient:
                        services.AddTransient(interfaceType, implementationType);
                        break;
                }
            }
        }
    }

}