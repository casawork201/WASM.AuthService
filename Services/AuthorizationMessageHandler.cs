using System.Net.Http.Headers;

namespace TestWASM.AuthLib.Services;

public class AuthorizationMessageHandler : DelegatingHandler
{
    private readonly AuthService _authService;

    public AuthorizationMessageHandler(AuthService authService)
    {
        _authService = authService;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Console.WriteLine($"[AuthHandler] → {request.Method} {request.RequestUri}");

        if (!string.IsNullOrEmpty(_authService.AccessToken) && _authService.IsExpired(_authService.AccessToken))
        {
            Console.WriteLine("[AuthHandler] Token expired — proactive refresh...");
            await _authService.TryRefreshAsync();
        }

        if (!string.IsNullOrEmpty(_authService.AccessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _authService.AccessToken);
            Console.WriteLine($"[AuthHandler] Attached Bearer token (len={_authService.AccessToken.Length})");
        }
        else
        {
            Console.WriteLine("[AuthHandler] No token available.");
        }

        var response = await base.SendAsync(request, cancellationToken);
        Console.WriteLine($"[AuthHandler] ← {(int)response.StatusCode} {request.RequestUri}");

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            Console.WriteLine("[AuthHandler] Got 401 — attempting reactive refresh...");
            var refreshed = await _authService.TryRefreshAsync();
            if (refreshed)
            {
                var retryRequest = await CloneRequestAsync(request);
                retryRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _authService.AccessToken);
                response = await base.SendAsync(retryRequest, cancellationToken);
                Console.WriteLine($"[AuthHandler] Retry result: {(int)response.StatusCode}");
            }
            else
            {
                Console.WriteLine("[AuthHandler] Reactive refresh failed — logging out.");
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