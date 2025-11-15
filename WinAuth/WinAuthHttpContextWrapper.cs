using Microsoft.AspNetCore.Http;

namespace WinAuth
{
    public class WinAuthHttpContextWrapper
    {
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
