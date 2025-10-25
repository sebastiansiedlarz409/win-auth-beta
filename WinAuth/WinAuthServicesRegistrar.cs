using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using WinAuth.Middleware;
using WinAuth.Session;

namespace WinAuth
{
    public static class WinAuthServicesRegistrar
    {
        public static void AddWinAuth(this IServiceCollection services)
        {
            services.AddSingleton<WinAuthManager>();
            services.AddSingleton<IWinAuthSessionManager, WinAuthSessionMemoryStorage>();
        }

        public static void UseWinAuth(this WebApplication app)
        {
            app.UseMiddleware<WinAuthMiddleware>();
        }
    }
}
