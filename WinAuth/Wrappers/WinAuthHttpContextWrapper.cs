using Microsoft.AspNetCore.Http;

namespace WinAuth.Wrappers
{
    internal class WinAuthHttpContextWrapper : IWinAuthHttpContextWrapper
    {
        public bool IsAuthenticated(HttpContext httpContext)
        {
            return httpContext.User.Identity!.IsAuthenticated;
        }

        public string? GetUserName(HttpContext httpContext)
        {
            return httpContext.User.Identity!.Name;
        }

        public string? GetCookieValue(HttpContext httpContext, string name)
        {
            var cookie = httpContext.Request.Cookies
                                .FirstOrDefault(t => t.Key == name);

            return cookie.Value;
        }

        public void SetHttpCookie(HttpContext httpContext, string name, string value, DateTime expirationDate)
        {
            //set cookie in context
            var options = new CookieOptions
            {
                Expires = expirationDate,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            };
            httpContext.Response.Cookies.Append(name, value, options);
        }
    }
}
