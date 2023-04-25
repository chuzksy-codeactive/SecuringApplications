using JwtApplication.Dtos;

namespace JwtApplication.Services
{
    public interface IAuthService
    {
        Task<SuccessResponse<AuthDto>> Login(UserLoginDTO model);
        Task<SuccessResponse<AuthDto>> GetRefreshToken(RefreshTokenDTO model);
        Task<SuccessResponse<GetSetPasswordDto>> SetPassword(SetPasswordDTO model);
        Task<SuccessResponse<object>> ResetPassword(ResetPasswordDTO model);
        Task<SuccessResponse<GetConifrmedTokenUserDto>> ConfirmToken(VerifyTokenDTO model);
    }
}
