using WinAuth.Session;

namespace WinAuth.Example.Auth
{
    public class WinAuthAccessDeniedHandler : IWinAuthAccessDeniedHandler
    {
        public Task OnRoleNotHighEnough(HttpContext httpContext)
        {
            if (httpContext.Request.Method == "GET")
                httpContext.Response.Redirect("/Home/Forbidden", false);
            else
                httpContext.Response.StatusCode = 401;
            return Task.CompletedTask;
        }

        public Task OnSessionExpired(HttpContext httpContext)
        {
            if (httpContext.Request.Method == "GET")
                httpContext.Response.Redirect("/Home/Forbidden", false);
            else
                httpContext.Response.StatusCode = 403;
            return Task.CompletedTask;
        }
    }
}
