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

            if(services.Where(s => s.ServiceType == typeof(IWinAuthSessionManager)).Count() == 0)
            {
                services.AddSingleton<IWinAuthSessionManager, WinAuthSessionMemoryStorage>();
            }
            else if(services.Where(s => s.ServiceType == typeof(IWinAuthSessionManager)).Count() > 1)
            {
                throw new Exception($"Implementation of IWinAuthSessionManager can be registere only once...");
            }
        }

        public static void UseWinAuth(this WebApplication app)
        {
            app.UseMiddleware<WinAuthMiddleware>();
        }
    }
}
