using WinAuth.Session;

namespace WinAuth.Example.Auth
{
    public class WinAuthAccessDeniedHandler : IWinAuthAccessDeniedHandler
    {
        public Task RequireAuthenticated(HttpContext httpContext)
        {
            if (httpContext.Request.Method == "GET")
                httpContext.Response.Redirect("/Home/Login", false);
            else
                httpContext.Response.StatusCode = 401;
            return Task.CompletedTask;
        }

        public Task RequireUnAuthenticated(HttpContext httpContext)
        {
            if (httpContext.Request.Method == "GET")
                httpContext.Response.Redirect("/Home/Forbidden", false);
            else
                httpContext.Response.StatusCode = 403;
            return Task.CompletedTask;
        }

        public Task RequireRole(HttpContext httpContext, string? userRole, string requiredRole)
        {
            if (httpContext.Request.Method == "GET")
                httpContext.Response.Redirect("/Home/Forbidden", false);
            else
                httpContext.Response.StatusCode = 403;
            return Task.CompletedTask;
        }
    }
}
