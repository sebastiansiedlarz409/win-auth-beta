using Microsoft.AspNetCore.Http;

namespace WinAuth
{
    public interface IWinAuthHttpContextWrapper
    {
        string? GetCookieValue(HttpContext httpContext, string name);
        string? GetUserName(HttpContext httpContext);
        bool IsAuthenticated(HttpContext httpContext);
        void SetHttpCookie(HttpContext httpContext, string name, string value, DateTime expirationDate);
    }
}