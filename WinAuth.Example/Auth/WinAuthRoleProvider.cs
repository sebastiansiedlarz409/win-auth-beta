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
        public Task<string?> GetRoleAsync(WinAuthSession session)
        {
            return Task.FromResult(Roles.USER.ToString())!;
        }

        public async Task<bool> HasAccessAsync(WinAuthSession session, string role)
        {
            object? targetRole = null;
            if(!Enum.TryParse(typeof(Roles), role.ToString(), out targetRole))
            {
                return false;
            }

            object? ur = await GetRoleAsync(session);
            if(ur is null)
            {
                return false;
            }

            object? userRole = null;
            if(!Enum.TryParse(typeof(Roles), ur.ToString(), out userRole))
            {
                return false;
            }

            if(userRole is null)
            {
                return false;
            }

            return ((Roles)targetRole) >= ((Roles)userRole);
        }
    }
}
