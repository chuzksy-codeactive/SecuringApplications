using JwtApplication.Dtos;
using JwtApplication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtApplication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthsController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthsController(IAuthService authService)
        {
            _authService = authService;
        }

        // <summary>Endpoint to login a user</summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("login")]
        [ProducesResponseType(typeof(SuccessResponse<AuthDto>), 200)]
        public async Task<IActionResult> LoginUser(UserLoginDTO model)
        {
            var response = await _authService.Login(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to generate a new access and refresh token
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("refresh-token")]
        [ProducesResponseType(typeof(SuccessResponse<RefreshTokenResponse>), 200)]
        public async Task<IActionResult> RefreshToken(RefreshTokenDTO model)
        {
            var response = await _authService.GetRefreshToken(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to initializes password reset
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("reset-password")]
        [ProducesResponseType(typeof(SuccessResponse<object>), 200)]
        public async Task<IActionResult> ForgotPassword(ResetPasswordDTO model)
        {
            var response = await _authService.ResetPassword(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to verify token
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("verify-token")]
        [ProducesResponseType(typeof(SuccessResponse<GetConifrmedTokenUserDto>), 200)]
        public async Task<IActionResult> VerifyToken(VerifyTokenDTO model)
        {
            var response = await _authService.ConfirmToken(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to set password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("set-password")]
        [ProducesResponseType(typeof(SuccessResponse<GetSetPasswordDto>), 200)]
        public async Task<IActionResult> SetPassword([FromForm] SetPasswordDTO model)
        {
            var response = await _authService.SetPassword(model);

            return Ok(response);
        }
    }
}
