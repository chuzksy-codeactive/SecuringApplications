using Microsoft.AspNetCore.Identity;

namespace JwtApplication.Domain
{
    public class RoleClaim : IdentityRoleClaim<Guid>
    {

    }

    public class Role : IdentityRole<Guid>
    {
        public Role() : base()
        { }
    }

    public class UserClaim : IdentityUserClaim<Guid>
    {
        public UserClaim() : base()
        { }
    }

    public class UserRole : IdentityUserRole<Guid>
    {
        public UserRole() : base()
        { }
    }
    public class UserLogin : IdentityUserLogin<Guid>
    {
        public UserLogin() : base()
        { }
    }
    public class UserToken : IdentityUserToken<Guid>
    {
    }
}
