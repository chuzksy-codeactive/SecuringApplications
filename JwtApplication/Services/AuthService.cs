using JwtApplication.Data;
using JwtApplication.Domain;
using JwtApplication.Dtos;
using JwtApplication.Enums;
using JwtApplication.Helpers;
using MapsterMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace JwtApplication.Services
{
    public class AuthService : IAuthService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<User> _userManager;
        private readonly IMapper _mapper;
        private readonly AppDbContext _context;
        public AuthService(IConfiguration configuration,
            UserManager<User> userManager,
            IMapper mapper,
            AppDbContext context)
        {
            _configuration = configuration;
            _userManager = userManager;
            _mapper = mapper;
            _context = context;
        }

        public async Task<SuccessResponse<GetConifrmedTokenUserDto>> ConfirmToken(VerifyTokenDTO model)
        {
            var token = await _context.Tokens.FirstOrDefaultAsync(x => x.Value == model.Token);
            if (token == null)
                throw new RestException(HttpStatusCode.NotFound, "The token is invalid or has expired");

            if (DateTime.Now >= token.ExpiresAt)
            {
                _context.Tokens.Remove(token);
                await _context.SaveChangesAsync();

                throw new RestException(HttpStatusCode.BadRequest, "Token is expired");
            }

            var user = await _context.Users.FirstOrDefaultAsync(x => x.Id == token.UserId);
            if (user == null)
                throw new RestException(HttpStatusCode.BadRequest, "Invalid Token");

            if (token.TokenType == ETokenType.InviteUser.ToString() &&
                (token.ExpiresAt - DateTime.Now) <= TimeSpan.FromMinutes(30))
            {
                token.ExpiresAt = token.ExpiresAt.AddMinutes(30);
                _context.Tokens.Update(token);
                await _context.SaveChangesAsync();
            }

            return new SuccessResponse<GetConifrmedTokenUserDto>
            {
                Message = "Token confirmed successfully",
                Data = new GetConifrmedTokenUserDto
                {
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            };
        }

        public async Task<SuccessResponse<AuthDto>> GetRefreshToken(RefreshTokenDTO model)
        {
            var userId = GetUserIdFromAccessToken(model.AccessToken);

            var user = await _context.Users.FirstOrDefaultAsync(x => x.Id == userId);
            if (user == null)
                throw new RestException(HttpStatusCode.NotFound, "User not found");

            var isRefreshTokenValid = ValidateRefreshToken(model.RefreshToken);
            if (!isRefreshTokenValid)
                throw new RestException(HttpStatusCode.NotFound, "Invalid token");

            var roles = await _userManager.GetRolesAsync(user);
            var tokenResponse = Authenticate(user, roles);

            var newRefreshToken = GenerateRefreshToken(user.Id);

            var tokenViewModel = new AuthDto
            {
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = newRefreshToken,
                ExpiresIn = tokenResponse.ExpiresIn
            };

            return new SuccessResponse<AuthDto>
            {
                Message = "Data retrieved successfully",
                Data = tokenViewModel
            };
        }

        private async Task<bool> ValidateUser(User user, string password)
        {
            var result = (user != null && await _userManager.CheckPasswordAsync(user, password));
            if (!result)
                return false;

            if (user != null && !user.Verified)
                return false;

            return result;
        }

        public async Task<SuccessResponse<AuthDto>> Login(UserLoginDTO model)
        {
            var email = model.Email.Trim().ToLower();
            var user = await _userManager.FindByEmailAsync(email);
            var authenticated = await ValidateUser(user, model.Password);

            if (!authenticated)
                throw new RestException(HttpStatusCode.Unauthorized, "Wrong Email or Password");

            if (!user.Verified || !user.IsActive)
                throw new RestException(HttpStatusCode.Unauthorized, "User is inactive");

            user.LastLogin = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            var roles = await _userManager.GetRolesAsync(user);

            var tokenResponse = Authenticate(user, roles);

            return new SuccessResponse<AuthDto>
            {
                Message = "Login successful",
                Data = new AuthDto
                {
                    AccessToken = tokenResponse.AccessToken,
                    ExpiresIn = tokenResponse.ExpiresIn,
                    RefreshToken = GenerateRefreshToken(user.Id),
                }
            };
        }

        public async Task<SuccessResponse<object>> ResetPassword(ResetPasswordDTO model)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == model.Email);
            if (user == null)
                throw new RestException(HttpStatusCode.NotFound, "User not found");

            var token = CustomToken.GenerateRandomString(128);
            var tokenEntity = new Token
            {
                UserId = user.Id,
                TokenType = ETokenType.ResetPassword.ToString(),
                Value = token
            };
            await _context.Tokens.AddAsync(tokenEntity);

            await _context.SaveChangesAsync();

            string emailLink = $"{_configuration["CLIENT_URL"]}/reset-password?token={token}";
            //Send email notification to the user to reset password

            return new SuccessResponse<object>
            {
                Message = "Password reset successfully",
            };
        }

        public async Task<SuccessResponse<GetSetPasswordDto>> SetPassword(SetPasswordDTO model)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");

            var token = await _context.Tokens.FirstOrDefaultAsync(x => x.Value == model.Token);
            if (token == null)
                throw new RestException(HttpStatusCode.NotFound, "The token is invalid or has expired");

            var isValid = CustomToken.IsTokenValid(token);
            if (!isValid)
                throw new RestException(HttpStatusCode.NotFound, "Token is invalid");

            var user = await _context.Users.FirstOrDefaultAsync(x => x.Id == token.UserId);
            if (user.Email != model.Email)
                throw new RestException(HttpStatusCode.NotFound, "Token is invalid");

            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, model.Password);
            user.UpdatedAt = DateTime.UtcNow;

            if (token.TokenType == ETokenType.InviteUser.ToString())
            {
                user.IsActive = true;
                user.Status = EUserStatus.ACTIVE.ToString();
                user.EmailConfirmed = true;
                user.Verified = true;
            }
            _context.Users.Update(user);

            _context.Tokens.Remove(token);
            await _context.SaveChangesAsync();

            return new SuccessResponse<GetSetPasswordDto>
            {
                Message = "Password set successfully",
                Data = _mapper.Map<GetSetPasswordDto>(user)
            };
        }

        private TokenReturnHelper Authenticate(User user, IList<string> roles)
        {
            var roleClaims = new List<Claim>();
            var claims = new List<Claim>
            {
                new Claim(ClaimTypeHelper.Email, user.Email),
                new Claim(ClaimTypeHelper.UserId, user.Id.ToString()),
                new Claim(ClaimTypeHelper.FirstName, user.FirstName),
                new Claim(ClaimTypeHelper.LastName, user.LastName),
            };

            foreach (var role in roles)
            {
                roleClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            claims.AddRange(roleClaims);

            var jwtSettings = _configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;
            var tokenExpireIn = string.IsNullOrEmpty(jwtSettings.GetSection("TokenLifespan").Value) ? int.Parse(jwtSettings.GetSection("TokenLifespan").Value) : 7;
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(jwtUserSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //Base on the user, you know which issuer/audience to assign
                Issuer = jwtSettings.GetSection("ValidIssuer").Value,
                Audience = jwtSettings.GetSection("ValidAudience").Value,
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(tokenExpireIn),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);

            return new TokenReturnHelper
            {
                ExpiresIn = tokenDescriptor.Expires,
                AccessToken = jwt
            };
        }

        private string GenerateRefreshToken(Guid userId)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(jwtUserSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = jwtSettings.GetSection("ValidIssuer").Value,
                Audience = jwtSettings.GetSection("ValidAudience").Value,
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypeHelper.UserId, userId.ToString())
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);

            return jwt;
        }

        private bool ValidateRefreshToken(string refreshToken)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtUserSecret)),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidIssuers = new string[] { "SampleApi", "SampleApi2" },
                ValidAudiences = new string[] { "www.sampleapi.com", "www.sampleapi2.com" },
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            _ = tokenHandler.ValidateToken(refreshToken, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            var expiryAt = jwtSecurityToken.ValidTo;
            if (DateTime.UtcNow > expiryAt)
                return false;
            return true;
        }

        private Guid GetUserIdFromAccessToken(string accessToken)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;

            var tokenValidationParamters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtUserSecret)),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidIssuers = new string[] { "SampleApi", "SampleApi2" },
                ValidAudiences = new string[] { "www.sampleapi.com", "www.sampleapi2.com" },
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParamters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                                                    StringComparison.InvariantCultureIgnoreCase))
            {
                throw new RestException(HttpStatusCode.BadRequest, "Invalid token");
            }

            var userId = principal.FindFirst(ClaimTypeHelper.UserId)?.Value;

            if (userId == null)
                throw new RestException(HttpStatusCode.BadRequest, $"MissingClaim: {ClaimTypeHelper.UserId}");

            return Guid.Parse(userId);
        }
    }
}
