using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace TestWASM.AuthLib.Services;

public class AuthorizationMessageHandler : DelegatingHandler
{
    private readonly AuthService _authService;
    private readonly ILogger<AuthorizationMessageHandler> _logger;

    public AuthorizationMessageHandler(
        AuthService authService, 
        ILogger<AuthorizationMessageHandler> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _logger.LogDebug("[AuthHandler] → {Method} {RequestUri}", request.Method, request.RequestUri);

        if (!string.IsNullOrEmpty(_authService.AccessToken) && _authService.IsExpired(_authService.AccessToken))
        {
            _logger.LogInformation("[AuthHandler] Token expired — proactive refresh...");
            await _authService.TryRefreshAsync();
        }

        if (!string.IsNullOrEmpty(_authService.AccessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _authService.AccessToken);
            _logger.LogDebug("[AuthHandler] Attached Bearer token.");
        }
        else
        {
            _logger.LogDebug("[AuthHandler] No token available.");
        }

        var response = await base.SendAsync(request, cancellationToken);
        _logger.LogDebug("[AuthHandler] ← {StatusCode} {RequestUri}", (int)response.StatusCode, request.RequestUri);

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            _logger.LogWarning("[AuthHandler] Got 401 — attempting reactive refresh...");

            var refreshed = await _authService.TryRefreshAsync();
            if (refreshed)
            {
                var retryRequest = await CloneRequestAsync(request);
                retryRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _authService.AccessToken);
                
                response = await base.SendAsync(retryRequest, cancellationToken);
                _logger.LogInformation("[AuthHandler] Retry result: {StatusCode}", (int)response.StatusCode);
            }
            else
            {
                _logger.LogWarning("[AuthHandler] Reactive refresh failed — logging out.");
                await _authService.LogoutAsync();
            }
        }

        return response;
    }

    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);
        if (original.Content != null)
        {
            var bytes = await original.Content.ReadAsByteArrayAsync();
            clone.Content = new ByteArrayContent(bytes);
            foreach (var header in original.Content.Headers)
                clone.Content.Headers.Add(header.Key, header.Value);
        }
        foreach (var header in original.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        return clone;
    }
}