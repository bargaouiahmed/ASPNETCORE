using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace ASPNETCORE.Models;



[Index(nameof(Username), IsUnique = true)]
public class User
{

    public int Id { get; set; }
    [MaxLength(50)]
    [Required]
    public string Username { get; set; } = string.Empty;

    public string HashedPassword { get; set; } = string.Empty;

    public string Role { get; set; } = UserRole.USER.ToString();

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;


    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }




}
