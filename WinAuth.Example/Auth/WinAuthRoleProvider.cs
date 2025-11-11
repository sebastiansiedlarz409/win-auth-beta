using System;
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

        public bool HasAccess(WinAuthSession session, object? role)
        {
            if(role is null)
            {
                return true;
            }

            object? targetRole = null;
            if(!Enum.TryParse(typeof(Roles), role.ToString(), out targetRole))
            {
                return false;
            }

            object? ur = GetRole(session);
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
