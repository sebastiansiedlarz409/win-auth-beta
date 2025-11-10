using WinAuth.Session;

namespace WinAuth.Example.Auth
{
    public enum Roles
    {
        SUPERADMIN = 0,
        ADMIN = 1,
        USER = 2,
    }

    public class WinAuthRoleProvider : IWinAuthRoleProvider
    {
        public object? GetRole(WinAuthSession session)
        {
            return Roles.SUPERADMIN.ToString();
        }
    }
}
