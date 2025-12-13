using Microsoft.AspNetCore.Http;

namespace WinAuth.Session
{
    public interface IWinAuthAccessDeniedHandler
    {
        /// <summary>
        /// Called when user is not logged or session expired
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        Task RequireAuthenticated(HttpContext httpContext);

        /// <summary>
        /// Called when user is logged
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        Task RequireUnAuthenticated(HttpContext httpContext);

        /// <summary>
        /// Called when user role is not enough to access
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        Task RequireRole(HttpContext httpContext, string? userRole, string requiredRole);
    }
}
