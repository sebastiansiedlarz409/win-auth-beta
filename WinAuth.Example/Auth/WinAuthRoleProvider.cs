using WinAuth.Session;

namespace WinAuth.Example.Auth
{
    public enum Roles
    {
        ADMIN = 1,
    }

    public class WinAuthRoleProvider : IWinAuthRoleProvider
    {
        public object? GetRole(WinAuthSession session)
        {
            return Roles.ADMIN.ToString();
        }
    }
}
