using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ASPNETCORE.DTO;
using ASPNETCORE.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace ASPNETCORE.Services;

public class AuthService(IConfiguration configuration,AppDbContext context):IAuthService
{
    public async Task<SerializedUser> RegisterUserAsync(RegisterUserRequest request)
    {
        if (await context.Users.AnyAsync(u => u.Username == request.Username))
        {
            throw new Exception("Username already exists");
        }


        User user = new();
        string hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            throw new Exception("Username and password cannot be empty");
        }
        user.Username = request.Username.Trim();
        user.HashedPassword = hashedPassword;
        context.Users.Add(user);
        await context.SaveChangesAsync();

        return new SerializedUser
        {
            Id = user.Id,
            Username = user.Username,
            Role = user.Role,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt
        };

    }






    public async Task<TokenPair> LoginUserAsync(string username, string password)
    {
        User? user = await context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
        {
            throw new Exception("Invalid username or password");
        }

        PasswordVerificationResult result = new PasswordHasher<User>().VerifyHashedPassword(user, user.HashedPassword, password);
        if (result == PasswordVerificationResult.Failed)
        {
            throw new Exception("Invalid username or password");
        }

        // Token generation logic would go here

        return new TokenPair
        {
            AccessToken = CreateToken(user),
            RefreshToken = await CreateRefreshToken(user)
        };
    }


    private string CreateToken(User user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Role, user.Role)
        };


        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["AppSettings:SecretKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var tokenDescriptor = new JwtSecurityToken(
            issuer: configuration["AppSettings:Issuer"],
            audience: configuration["AppSettings:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds
        );
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }

    private async Task<string> CreateRefreshToken(User user)
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        //This is a minimal implementation, in practice you shouldn't include the user id in the refresh token
        //but this is done here to advocate for looking up users by id for performance gains due to PK indexing
        string refreshToken = Convert.ToBase64String(randomNumber)+"?Id="+user.Id.ToString();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await context.SaveChangesAsync();
        return refreshToken;

    }

    public async Task<TokenPair> RefreshAccessTokenAsync(string refreshToken)
    {
        var parts = refreshToken.Split("?Id=");
        if (parts.Length < 2 || !int.TryParse(parts[1], out var userId))
        {
            throw new Exception("Invalid or expired refresh token");
        }

        User? user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId && u.RefreshToken == refreshToken);
        if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            throw new Exception("Invalid or expired refresh token");
        }

        return new TokenPair
        {
            AccessToken = CreateToken(user),
            RefreshToken = refreshToken
        };
    }

    

}
