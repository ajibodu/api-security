using System.Reflection;
using Microsoft.Extensions.DependencyInjection;

namespace Api.Security.Authentication.Core.DependencyInjection;

/// <summary>
/// Provides extension methods for registering services in the dependency injection container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Scans loaded assemblies for implementations of <typeparamref name="TInterface"/> and registers them with the specified lifetime.
    /// </summary>
    /// <typeparam name="TInterface">The interface type to scan for.</typeparam>
    /// <param name="services">The service collection to register with.</param>
    /// <param name="lifetime">The service lifetime (default: Scoped).</param>
    /// <exception cref="ArgumentException">Thrown if <typeparamref name="TInterface"/> is not an interface.</exception>
    public static void FindAndRegisterServices<TInterface>(this IServiceCollection services, ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        ArgumentNullException.ThrowIfNull(services);
        
        var libraryAssembly = typeof(TInterface).Assembly;
        var assemblies = AppDomain.CurrentDomain.GetAssemblies()
            .Where(a => a.GetReferencedAssemblies().Any(r => r.FullName == libraryAssembly.FullName))
            .ToList();
        
        // Always include the entry assembly and executing assembly if not null
        var entryAssembly = Assembly.GetEntryAssembly();
        if (entryAssembly != null)
            assemblies.Add(entryAssembly);
        var executingAssembly = Assembly.GetExecutingAssembly();
        if (executingAssembly != null)
            assemblies.Add(executingAssembly);
        
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