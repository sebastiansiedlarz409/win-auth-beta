using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using WinAuth.Exceptions;
using WinAuth.Middleware;
using WinAuth.Session;

namespace WinAuth
{
    public static class WinAuthServicesRegistrar
    {
        /// <summary>
        /// Configure WinAuth
        /// </summary>
        /// <param name="domainName">Target domain name</param>
        /// <param name="sessionLifeTime">Session life time in minutes</param>
        /// <exception cref="WinAuthSetupException">Thrown when none or more than one IWinAuthSessionManager implementation has been registered</exception>
        public static void AddWinAuth(this IServiceCollection services, string domainName, int sessionLifeTime)
        {
            if(sessionLifeTime < 5)
            {
                throw new WinAuthSetupException($"Session life time must be greater or equal than 5 minutes...");
            }

            if (services.Where(s => s.ServiceType == typeof(IWinAuthSessionManager)).Count() == 0)
            {
                services.AddSingleton<IWinAuthSessionManager, WinAuthSessionMemoryStorage>();
            }
            else if (services.Where(s => s.ServiceType == typeof(IWinAuthSessionManager)).Count() > 1)
            {
                throw new WinAuthSetupException($"Implementation of IWinAuthSessionManager can be registere only once...");
            }

            services.AddSingleton<WinAuthManager>(t =>
            {
                //if user did not regiseter own manager code above register default one
                //null value never happen
                IWinAuthSessionManager? sm = t.GetService<IWinAuthSessionManager>()!;
                return new WinAuthManager(sm, domainName, sessionLifeTime);
            });
        }

        /// <summary>
        /// Add middlware to pipeline
        /// </summary>
        /// <param name="assembly">Main assembly/Controllers assembly</param>
        public static void UseWinAuth(this WebApplication app, Assembly assembly)
        {
            app.UseMiddleware<WinAuthMiddleware>(assembly);
        }
    }
}
