using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using System.Runtime.InteropServices;
using WinAuth.Exceptions;
using WinAuth.Middleware;
using WinAuth.Session;

namespace WinAuth
{
    public static class WinAuthServicesRegistrar
    {
        /// <summary>
        /// Configure WinAuth and check dependencies
        /// </summary>
        /// <param name="domainName">Target domain name</param>
        /// <param name="sessionLifeTime">Session life time in minutes</param>
        /// <exception cref="WinAuthSetupException">Thrown when setup failed due to wrong platform, too short session lifetime or lack of required services in DI</exception>
        public static void AddWinAuth(this IServiceCollection services, string domainName, int sessionLifeTime)
        {
            //check platform
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new WinAuthSetupException($"Only windows enviroment is supported at the moment...");
            }

            //check session lifetime
            /*if (sessionLifeTime < 5)
            {
                throw new WinAuthSetupException($"Session life time must be greater or equal than 5 minutes...");
            }*/

            //check if session storage provider has been registered
            if (services.Where(s => s.ServiceType == typeof(IWinAuthSessionStorage)).Count() == 0)
            {
                throw new WinAuthSetupException($"Implementation of IWinAuthSessionManager not found...");
            }

            //context wrapper
            services.AddSingleton<WinAuthHttpContextWrapper>();
            services.AddSingleton<IWinAuthCredentialValidator, WinAuthCredentialValidator>();

            //register auth manager
            services.AddSingleton(t =>
            {
                IWinAuthSessionStorage sm = t.GetService<IWinAuthSessionStorage>()!;
                IWinAuthCredentialValidator cv = t.GetService<IWinAuthCredentialValidator>()!;
                IWinAuthRoleProvider? rp = t.GetService<IWinAuthRoleProvider>();
                WinAuthHttpContextWrapper cw = t.GetService<WinAuthHttpContextWrapper>()!;
                return new WinAuthManager(cw, cv, sm, rp, domainName, sessionLifeTime);
            });
        }

        /// <summary>
        /// Add middlware to pipeline
        /// </summary>
        /// <param name="assembly">MVC assembly</param>
        public static void UseWinAuth(this WebApplication app, Assembly assembly, string loginPath, string forbiddenPath)
        {
            if (string.IsNullOrEmpty(loginPath))
            {
                throw new WinAuthSetupException($"Invalid login route name...");
            }

            if (string.IsNullOrEmpty(forbiddenPath))
            {
                throw new WinAuthSetupException($"Invalid forbidden route name...");
            }

            //add middleware to pipe line
            app.UseMiddleware<WinAuthMiddleware>(assembly, loginPath, forbiddenPath);
        }
    }
}
