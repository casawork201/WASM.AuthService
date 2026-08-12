using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using TestWASM.AuthLib.Models;

namespace TestWASM.AuthLib.Services;

public class AuthService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IJSRuntime _js;
    private readonly ILogger<AuthService> _logger;

    private const string TokenKey = "auth_token";
    private const string RefreshKey = "auth_refresh_token";
    private const string EmailKey = "auth_email";

    public string? AccessToken { get; private set; }
    public string? RefreshToken { get; private set; }
    public string? Email { get; private set; }
    public List<string> Roles { get; private set; } = new();
    public bool IsLoggedIn => !string.IsNullOrEmpty(AccessToken);
    public bool IsInitialized { get; private set; }

    public event Action? OnChange;

    public AuthService(IHttpClientFactory httpClientFactory, IJSRuntime js, ILogger<AuthService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _js = js;
        _logger = logger;
    }

    public async Task InitializeAsync()
    {
        if (IsInitialized) return;

        try
        {
            AccessToken = await _js.InvokeAsync<string?>("localStorage.getItem", TokenKey);
            RefreshToken = await _js.InvokeAsync<string?>("localStorage.getItem", RefreshKey);
            Email = await _js.InvokeAsync<string?>("localStorage.getItem", EmailKey);

            _logger.LogDebug("[AuthService.Init] Session restored. Authenticated: {IsLoggedIn}", IsLoggedIn);

            if (!string.IsNullOrEmpty(AccessToken))
            {
                if (IsExpired(AccessToken))
                {
                    _logger.LogDebug("[AuthService.Init] Stored token expired, attempting background refresh...");
                    var refreshed = await TryRefreshAsync();
                    if (!refreshed)
                    {
                        await ClearAsync();
                    }
                }
                else
                {
                    Roles = ExtractRoles(AccessToken);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[AuthService.Init] Error initializing auth state from storage.");
        }
        finally
        {
            IsInitialized = true;
            OnChange?.Invoke();
        }
    }

    public async Task<(bool Success, string? Error)> LoginAsync(string email, string password)
    {
        var client = _httpClientFactory.CreateClient("AuthApi");
        var response = await client.PostAsJsonAsync("api/auth/login", new LoginRequestDto
        {
            Email = email,
            Password = password
        });

        _logger.LogDebug("[AuthService.Login] Response Status: {StatusCode}", response.StatusCode);

        if (!response.IsSuccessStatusCode)
            return (false, "Invalid email or password");

        var raw = await response.Content.ReadAsStringAsync();

        TokenResponseDto? data;
        try
        {
            data = JsonSerializer.Deserialize<TokenResponseDto>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[AuthService.Login] Failed to deserialize auth response.");
            return (false, "Could not parse server response");
        }

        if (data is null || string.IsNullOrEmpty(data.Token))
        {
            return (false, "Unexpected response from auth server");
        }

        var effectiveEmail = string.IsNullOrEmpty(data.Email) ? email : data.Email;
        await SetSessionAsync(data.Token, data.RefreshToken, effectiveEmail, data.Roles ?? new());
        
        _logger.LogInformation("[AuthService.Login] User login successful.");
        return (true, null);
    }
    public async Task<(bool Success, string? Error)> RegisterAsync(RegisterRequestDto model)
    {
        var client = _httpClientFactory.CreateClient("AuthApi");
        var response = await client.PostAsJsonAsync("api/auth/register", model);

        _logger.LogDebug("[AuthService.Register] Response Status: {StatusCode}", response.StatusCode);

        if (response.IsSuccessStatusCode)
        {
            _logger.LogInformation("[AuthService.Register] Registration successful.");
            return (true, null);
        }

        var raw = await response.Content.ReadAsStringAsync();
        _logger.LogWarning("[AuthService.Register] Registration failed: {Body}", raw);
        return (false, "Registration failed. Please check your details and try again.");
    }
    public async Task<bool> TryRefreshAsync()
    {
        if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(RefreshToken))
            return false;

        var client = _httpClientFactory.CreateClient("AuthApi");
        var response = await client.PostAsJsonAsync("api/auth/refresh-token", new RefreshTokenRequestDto
        {
            Email = Email,
            RefreshToken = RefreshToken
        });

        _logger.LogDebug("[AuthService.Refresh] Response Status: {StatusCode}", response.StatusCode);

        if (!response.IsSuccessStatusCode)
            return false;

        var raw = await response.Content.ReadAsStringAsync();

        TokenResponseDto? data;
        try
        {
            data = JsonSerializer.Deserialize<TokenResponseDto>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch
        {
            return false;
        }

        if (data is null || string.IsNullOrEmpty(data.Token))
            return false;

        var newRefresh = string.IsNullOrEmpty(data.RefreshToken) ? RefreshToken : data.RefreshToken;
        await SetSessionAsync(data.Token, newRefresh, Email, data.Roles ?? Roles);
        return true;
    }

    public async Task LogoutAsync() => await ClearAsync();

    private async Task SetSessionAsync(string token, string? refreshToken, string email, List<string> roles)
    {
        AccessToken = token;
        RefreshToken = refreshToken;
        Email = email;
        Roles = roles;

        await _js.InvokeVoidAsync("localStorage.setItem", TokenKey, token);
        if (!string.IsNullOrEmpty(refreshToken))
            await _js.InvokeVoidAsync("localStorage.setItem", RefreshKey, refreshToken);
        await _js.InvokeVoidAsync("localStorage.setItem", EmailKey, email);

        OnChange?.Invoke();
    }

    private async Task ClearAsync()
    {
        AccessToken = null;
        RefreshToken = null;
        Email = null;
        Roles = new();

        await _js.InvokeVoidAsync("localStorage.removeItem", TokenKey);
        await _js.InvokeVoidAsync("localStorage.removeItem", RefreshKey);
        await _js.InvokeVoidAsync("localStorage.removeItem", EmailKey);

        OnChange?.Invoke();
    }

    public bool IsExpired(string jwt)
    {
        try
        {
            var parsed = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
            return DateTime.UtcNow >= parsed.ValidTo;
        }
        catch
        {
            return true;
        }
    }

    private List<string> ExtractRoles(string jwt)
    {
        try
        {
            var parsed = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
            return parsed.Claims.Where(c => c.Type == "role" || c.Type.EndsWith("/role"))
                                 .Select(c => c.Value).ToList();
        }
        catch
        {
            return new();
        }
    }
}