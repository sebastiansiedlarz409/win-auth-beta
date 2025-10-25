using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using WinAuth.Middleware;
using WinAuth.Session;

namespace WinAuth
{
    public static class WinAuthServicesRegistrar
    {
        public static void AddWinAuth(this IServiceCollection services, string domainName)
        {
            if (services.Where(s => s.ServiceType == typeof(IWinAuthSessionManager)).Count() == 0)
            {
                services.AddSingleton<IWinAuthSessionManager, WinAuthSessionMemoryStorage>();
            }
            else if (services.Where(s => s.ServiceType == typeof(IWinAuthSessionManager)).Count() > 1)
            {
                throw new Exception($"Implementation of IWinAuthSessionManager can be registere only once...");
            }

            services.AddSingleton<WinAuthManager>(t =>
            {
                //if user did not regiseter own manager code above register default one
                //null value never happen
                IWinAuthSessionManager? sm = t.GetService<IWinAuthSessionManager>()!;
                return new WinAuthManager(sm, domainName);
            });
        }

        public static void UseWinAuth(this WebApplication app)
        {
            app.UseMiddleware<WinAuthMiddleware>();
        }
    }
}
