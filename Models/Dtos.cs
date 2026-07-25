using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components.Forms;

namespace TestWASM.AuthLib.Models;

public class MaterialDto
{
    [Required, StringLength(20)]
    public string StockCode { get; set; } = string.Empty!;
    [Required, StringLength(450)]
    public string Description { get; set; } = string.Empty!;
    [Required]
    public decimal Quantity { get; set; } = 0;
    [Required, StringLength(4)]
    public string UnitOfMeasurement { get; set; } = string.Empty!;
    [Required, StringLength(40)]
    public string LocationCode { get; set; } = string.Empty!;
}
public class RegisterRequestDto
{
    public RegisterRequestDto(){}
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [MinLength(6, ErrorMessage = "Security Key must be at least 6 characters")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirmation is required")]
    [Compare("Password", ErrorMessage = "Security Keys do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    public string? Role { get; set; } = "User";
}
public class JwtAuthOptionsDto
{
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string Key { get; set; } = string.Empty;
    public int RefreshTokenExpiresMinutes { get; set; } = 60;
}
public class TokenResponseDto
{
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public List<string>? Roles { get; set; }
    public string? UserId { get; set; }
}
public class RefreshTokenRequestDto
{
    public string Email { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
}


public class ImageUploadDto
{
    public string CommonName { get; set; } = string.Empty!;
    public IBrowserFile? Image { get; set; }
}

public class DisplayImageDto
{
    public Guid Id { get; set; }    
    public string CommonName { get; set; } = string.Empty!;
    public DateTime UploadedAt { get; set; }
    public string ContentType { get; set; } = string.Empty!;
    public byte[] Bytes { get; set; } = null!;
}

// DTO helper
public class BulkTransferDto
{
    public List<Guid> Ids { get; set; } = new();
    public Guid NewSpeciesId { get; set; }
}



public class UserDto
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
}
public class CreateRoleModel
{
    [Required(ErrorMessage = "Role name is required.")]
    [MinLength(3, ErrorMessage = "Role name must be at least 3 characters.")]
    public string RoleName { get; set; } = string.Empty;
}

public class UpdateRoleModel
{
    [Required(ErrorMessage = "New role name is required.")]
    [MinLength(3, ErrorMessage = "Role name must be at least 3 characters.")]
    public string NewRoleName { get; set; } = string.Empty;
}
public class AssignRoleModel
{
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required, MinLength(3)]
    public string RoleName { get; set; } = string.Empty;
}
public class AddRoleModel
{
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;

}
public class LoginRequestDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;
}