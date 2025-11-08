using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using System.Runtime.InteropServices;
using WinAuth.Attributes;
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
            //if any register default one
            if (services.Where(s => s.ServiceType == typeof(IWinAuthSessionStorage)).Count() == 0)
            {
                services.AddSingleton<IWinAuthSessionStorage, WinAuthSessionMemoryStorage>();
            }
            else if (services.Where(s => s.ServiceType == typeof(IWinAuthSessionStorage)).Count() > 1)
            {
                throw new WinAuthSetupException($"Implementation of IWinAuthSessionManager can be registere only once...");
            }

            //register auth manager
            services.AddSingleton<WinAuthManager>(t =>
            {
                IWinAuthSessionStorage? sm = t.GetService<IWinAuthSessionStorage>()!;
                return new WinAuthManager(sm, domainName, sessionLifeTime);
            });
        }

        /// <summary>
        /// Add middlware to pipeline
        /// </summary>
        /// <param name="assembly">Main assembly/Controllers assembly</param>
        public static void UseWinAuth(this WebApplication app, Assembly assembly, string loginRoutePattern = "login")
        {
            if (string.IsNullOrEmpty(loginRoutePattern))
            {
                throw new WinAuthSetupException($"Invalid login route name...");
            }

            //add login route to routes table base on WinAuthAccessAttribute
            CreateLoginRoute(app, assembly, loginRoutePattern);

            app.UseMiddleware<WinAuthMiddleware>(assembly);
        }

        /// <summary>
        /// Scan assesmby for login action
        /// </summary>
        /// <param name="assembly">Assembly to scan</param>
        /// <exception cref="WinAuthRouteException"></exception>
        private static void CreateLoginRoute(WebApplication app, Assembly assembly, string loginRoutePattern)
        {
            var controllers = assembly.GetTypes()
                .Where(t => t.Name.Contains($"Controller"));

            //scan for all action
            List<(Type, MethodInfo)> controllersActions = new List<(Type, MethodInfo)>();
            foreach (var controller in controllers)
            {
                var actions = controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .Where(t => t.ReturnType == typeof(IActionResult) || t.ReturnType == typeof(Task<IActionResult>))
                    .ToList();

                actions.ForEach(t => controllersActions.Add((controller, t)));
            }

            foreach (var action in controllersActions)
            {
                var attribute = action.Item2.GetCustomAttribute(typeof(WinAuthAccessAttribute));
                if (attribute is { })
                {
                    var access = (WinAuthAccessAttribute)attribute;
                    if (access.Access == WinAuthAccess.Login)
                    {
                        var controllerName = action.Item1.Name.Replace("Controller", "");
                        var actionName = action.Item2.Name;

                        app.MapControllerRoute(
                            name: "WinAuthLoginRoute", 
                            pattern: loginRoutePattern,
                            defaults: new { controller = controllerName, action = actionName })
                            .WithStaticAssets();

                        return;
                    }
                }
            }

            throw new WinAuthRouteException("Cant create login route... Use WinAuthAccess.Login on login action...");
        }
    }
}
