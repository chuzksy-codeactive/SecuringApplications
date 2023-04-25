using System.Security.Claims;

namespace JwtApplication.Helpers
{
    public class ClaimTypeHelper
    {
        public static string UserId { get; set; } = "UserId";
        public static string Email { get; set; } = "Email";
        public static string FirstName { get; set; } = "FirstName";
        public static string LastName { get; set; } = "LastName";
        public static string PhoneNumber { get; set; } = "PhoneNumber";
        public static string Roles { get; set; } = ClaimTypes.Role;
    }
}
