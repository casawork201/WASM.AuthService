using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace TestWASM.AuthLib.Services;

public class CustomWasmAuthStateProvider : AuthenticationStateProvider
{
    private readonly AuthService _authService;

    public CustomWasmAuthStateProvider(AuthService authService)
    {
        _authService = authService;
        _authService.OnChange += () => NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        ClaimsIdentity identity;

        if (_authService.IsLoggedIn)
        {
            var claims = new List<Claim> { new(ClaimTypes.Name, _authService.Email ?? "") };
            claims.AddRange(_authService.Roles.Select(r => new Claim(ClaimTypes.Role, r)));
            identity = new ClaimsIdentity(claims, "jwt");
        }
        else
        {
            identity = new ClaimsIdentity();
        }

        return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(identity)));
    }
}