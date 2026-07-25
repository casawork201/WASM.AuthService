using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using TestWASM.AuthLib.Services;



namespace TestWASM.AuthLib.Extensions;

public static class AuthLibServiceCollectionExtensions
{
    /// <summary>
    /// Registers client-side JWT auth: AuthService, message handler, and AuthenticationStateProvider.
    /// Also registers a named "Default" HttpClient (pointed at the host base address, with the
    /// auth handler attached) and a named "AuthApi" HttpClient (pointed at authApiBaseUrl, no handler).
    /// </summary>
    public static IServiceCollection AddClientAuth(
        this IServiceCollection services,
        string hostBaseAddress,
        string authApiBaseUrl)
    {
        services.AddTransient<AuthorizationMessageHandler>();

        services.AddScoped(sp =>
        {
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            return factory.CreateClient("Default");
        });

        services.AddHttpClient("Default", client =>
        {
            client.BaseAddress = new Uri(hostBaseAddress);
        }).AddHttpMessageHandler<AuthorizationMessageHandler>();

        services.AddHttpClient("AuthApi", client =>
        {
            client.BaseAddress = new Uri(authApiBaseUrl);
        });

        services.AddSingleton<AuthService>();
        services.AddScoped<AuthenticationStateProvider, CustomWasmAuthStateProvider>();
        services.AddAuthorizationCore();

        return services;
    }
}