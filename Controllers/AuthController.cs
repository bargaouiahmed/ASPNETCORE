using ASPNETCORE.DTO;
using ASPNETCORE.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETCORE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {



        [HttpPost("register")]
        public async Task<ActionResult<SerializedUser>> RegisterUser([FromBody] RegisterUserRequest request)
        {
            try
            {
                SerializedUser user = await authService.RegisterUserAsync(request);
                return Ok(user);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
        [HttpPost("login")]
        public async Task<ActionResult<TokenPair>> LoginUser([FromBody] RegisterUserRequest request)
        {
            try
            {
                TokenPair tokens = await authService.LoginUserAsync(request.Username, request.Password);
                return Ok(tokens);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
        [HttpGet("refresh")]
        public async Task<ActionResult<TokenPair>> RefreshAccessToken([FromQuery] string refreshToken)
        {
            try
            {
                TokenPair tokens = await authService.RefreshAccessTokenAsync(refreshToken);
                return Ok(tokens);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

    [Authorize]
    [HttpGet("protected")]
    public ActionResult<string> ProtectedEndpoint()
        {
        var username = User.Identity?.Name;
        return Ok("You have accessed a protected endpoint! Hello, " + username);
    }
    }

    
}
