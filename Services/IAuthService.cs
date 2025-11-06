using System;
using ASPNETCORE.DTO;

namespace ASPNETCORE.Services;

public interface IAuthService
{


    public Task<SerializedUser> RegisterUserAsync(RegisterUserRequest request);
    public Task<TokenPair> LoginUserAsync(string username, string password);
    


    public Task<TokenPair> RefreshAccessTokenAsync(string refreshToken);

}
