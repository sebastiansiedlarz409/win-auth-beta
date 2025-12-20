using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using System.Runtime.InteropServices;
using WinAuth.Wrappers;
using WinAuth.Exceptions;
using WinAuth.Middleware;
using WinAuth.Session;

namespace WinAuth
{
    public static class WinAuthServicesRegistrar
    {
        /// <summary>
        /// Enable WinAuth
        /// </summary>
        /// <param name="domainName">Target domain name</param>
        /// <param name="sessionLifeTime">Session life time in minutes</param>
        /// <exception cref="WinAuthSetupException">
        /// Thrown when setup failed due to wrong platform, too short session lifetime or lack of required services registration
        /// </exception>
        public static void AddWinAuth(this IServiceCollection services, string domainName, int sessionLifeTime)
        {
            //check platform
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new WinAuthSetupException($"Only windows enviroment is supported at the moment...");
            }

            //check session lifetime
            if (sessionLifeTime < 5)
            {
                throw new WinAuthSetupException($"Session life time must be greater or equal than 5 minutes...");
            }

            //check if session storage provider has been registered
            if (services.Where(s => s.ServiceType == typeof(IWinAuthSessionStorage)).Count() == 0)
            {
                throw new WinAuthSetupException($"Implementation of IWinAuthSessionManager not found...");
            }

            //context wrapper
            services.AddSingleton<IWinAuthHttpContextWrapper, WinAuthHttpContextWrapper>();
            services.AddSingleton<IWinAuthCredentialValidator, WinAuthCredentialValidator>();

            //register auth manager
            services.AddScoped(t =>
            {
                IWinAuthSessionStorage sm = t.GetRequiredService<IWinAuthSessionStorage>()!;
                IWinAuthCredentialValidator cv = t.GetRequiredService<IWinAuthCredentialValidator>()!;
                IWinAuthHttpContextWrapper cw = t.GetRequiredService<IWinAuthHttpContextWrapper>()!;
                IWinAuthRoleProvider? rp = t.GetService<IWinAuthRoleProvider>();

                return new WinAuthManager(cw, cv, sm, rp, domainName, sessionLifeTime);
            });
        }

        /// <summary>
        /// Insert middleware to application pipeline
        /// </summary>
        /// <param name="assembly">MVC Assembly</param>
        public static void UseWinAuth(this WebApplication app, Assembly assembly)
        {
            //add middleware to pipe line
            app.UseMiddleware<WinAuthMiddleware>(assembly);
        }
    }
}
