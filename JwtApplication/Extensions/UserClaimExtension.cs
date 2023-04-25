using JwtApplication.Helpers;
using System.Security.Claims;

namespace JwtApplication.Extensions
{
    public static class UserClaimsExtension
    {
        public static UserClaims UserClaims(this ClaimsPrincipal user)
        {
            var userId = user.Claims.Where(x => x.Type == ClaimTypeHelper.UserId)?.FirstOrDefault()?.Value;
            var email = user.Claims.Where(x => x.Type == ClaimTypeHelper.Email)?.FirstOrDefault()?.Value;
            var roles = user.Claims.Where(x => x.Type == ClaimTypeHelper.Roles)?.Select(x => x.Value);
            var firstName = user.Claims.Where(x => x.Type == ClaimTypeHelper.FirstName)?.FirstOrDefault()?.Value;
            var lastName = user.Claims.Where(x => x.Type == ClaimTypeHelper.LastName)?.FirstOrDefault()?.Value;

            var getUserIdGuid = Guid.TryParse(userId, out Guid userIdGuid);

            return new UserClaims
            {
                UserId = getUserIdGuid ? userIdGuid : Guid.Empty,
                Email = email,

                Roles = roles,
                FirstName = firstName,
                LastName = lastName
            };
        }
    }

    public class UserClaims
    {
        public Guid UserId { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public IEnumerable<string> Roles { get; set; }
    }
}
