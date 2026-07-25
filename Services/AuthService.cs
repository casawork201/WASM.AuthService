using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.JSInterop;
using TestWASM.AuthLib.Models;


namespace TestWASM.AuthLib.Services;

public class AuthService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IJSRuntime _js;
    private const string TokenKey = "auth_token";
    private const string RefreshKey = "auth_refresh_token";
    private const string EmailKey = "auth_email";

    public string? AccessToken { get; private set; }
    public string? RefreshToken { get; private set; }
    public string? Email { get; private set; }
    public List<string> Roles { get; private set; } = new();
    public bool IsLoggedIn => !string.IsNullOrEmpty(AccessToken);

    public event Action? OnChange;

    public AuthService(IHttpClientFactory httpClientFactory, IJSRuntime js)
    {
        _httpClientFactory = httpClientFactory;
        _js = js;
    }

    public async Task InitializeAsync()
    {
        try
        {
            AccessToken = await _js.InvokeAsync<string?>("localStorage.getItem", TokenKey);
            RefreshToken = await _js.InvokeAsync<string?>("localStorage.getItem", RefreshKey);
            Email = await _js.InvokeAsync<string?>("localStorage.getItem", EmailKey);

            Console.WriteLine($"[AuthService.Init] Loaded from storage — Email='{Email}', HasToken={!string.IsNullOrEmpty(AccessToken)}, HasRefresh={!string.IsNullOrEmpty(RefreshToken)}");

            if (!string.IsNullOrEmpty(AccessToken))
            {
                if (IsExpired(AccessToken))
                {
                    Console.WriteLine("[AuthService.Init] Stored token expired, attempting refresh...");
                    var refreshed = await TryRefreshAsync();
                    if (!refreshed)
                    {
                        Console.WriteLine("[AuthService.Init] Refresh failed, clearing session.");
                        await ClearAsync();
                    }
                }
                else
                {
                    Roles = ExtractRoles(AccessToken);
                }
            }
            OnChange?.Invoke();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AuthService.Init] Exception: {ex.Message}");
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

        var raw = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"[AuthService.Login] Status={response.StatusCode} Body={raw}");

        if (!response.IsSuccessStatusCode)
            return (false, "Invalid email or password");

        TokenResponseDto? data;
        try
        {
            data = JsonSerializer.Deserialize<TokenResponseDto>(raw, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AuthService.Login] Deserialize failed: {ex.Message}");
            return (false, "Could not parse server response");
        }

        if (data is null || string.IsNullOrEmpty(data.Token))
        {
            Console.WriteLine("[AuthService.Login] Token missing in response.");
            return (false, "Unexpected response from auth server");
        }

        Console.WriteLine($"[AuthService.Login] Parsed — Token(len)={data.Token.Length}, RefreshToken='{data.RefreshToken}', ResponseEmail='{data.Email}', Roles=[{string.Join(",", data.Roles ?? new())}]");

        var effectiveEmail = string.IsNullOrEmpty(data.Email) ? email : data.Email;
        await SetSessionAsync(data.Token, data.RefreshToken, effectiveEmail, data.Roles ?? new());
        return (true, null);
    }

    public async Task<bool> TryRefreshAsync()
    {
        Console.WriteLine($"[AuthService.Refresh] Attempting refresh — Email='{Email}', HasRefreshToken={!string.IsNullOrEmpty(RefreshToken)}");

        if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(RefreshToken))
        {
            Console.WriteLine("[AuthService.Refresh] Aborting — missing Email or RefreshToken.");
            return false;
        }

        var client = _httpClientFactory.CreateClient("AuthApi");
        var response = await client.PostAsJsonAsync("api/auth/refresh-token", new RefreshTokenRequestDto
        {
            Email = Email,
            RefreshToken = RefreshToken
        });

        var raw = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"[AuthService.Refresh] Status={response.StatusCode} Body={raw}");

        if (!response.IsSuccessStatusCode)
            return false;

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

        Console.WriteLine($"[AuthService.SetSession] Stored — Email='{email}', RefreshToken='{refreshToken}'");

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