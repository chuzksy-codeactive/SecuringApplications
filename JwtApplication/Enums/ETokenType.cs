using System.ComponentModel;

namespace JwtApplication.Enums
{
    public enum ETokenType
    {
        [Description("Create New User")]
        InviteUser,
        [Description("Reset Password")]
        ResetPassword
    }

    public enum EUserStatus
    {
        [Description("ACTIVE")]
        ACTIVE = 1,
        [Description("PENDING")]
        PENDING = 2,
        [Description("DEACTIVATE")]
        DEACTIVATE = 3,
    }

    public enum ERole
    {
        [Description("SUPERADMIN")]
        SUPERADMIN = 1,
        [Description("ADMIN")]
        ADMIN = 2
    }
}
