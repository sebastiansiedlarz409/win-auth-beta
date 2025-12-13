using Microsoft.AspNetCore.Http;

namespace WinAuth.Wrappers
{
    public interface IWinAuthHttpContextWrapper
    {
        string? GetCookieValue(HttpContext httpContext, string name);

        void SetHttpCookie(HttpContext httpContext, string name, string value, DateTime expirationDate);
    }
}