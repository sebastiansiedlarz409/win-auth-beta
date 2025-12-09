using Microsoft.AspNetCore.Http;

namespace WinAuth.Session
{
    public interface IWinAuthAccessDeniedHandler
    {
        /// <summary>
        /// Called when user is not logged
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        Task OnSessionExpired(HttpContext httpContext);

        /// <summary>
        /// Called when user role is not enough to access
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        Task OnRoleNotHighEnough(HttpContext httpContext);
    }
}
