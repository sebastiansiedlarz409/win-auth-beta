using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using WinAuth.Attributes;
using WinAuth.Exceptions;
using WinAuth.Session;

namespace WinAuth.Middleware
{
    public sealed class WinAuthMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly Assembly _assembly;

        private WinAuthManager? _authManager;
        private readonly IWinAuthAccessDeniedHandler? _accessDeniedHandler;

        public WinAuthMiddleware(RequestDelegate next,
                                 Assembly assembly,
                                 IWinAuthAccessDeniedHandler? accessDeniedHandler = null)
        {
            _next = next;
            _assembly = assembly;

            _accessDeniedHandler = accessDeniedHandler;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            //skip non-mvc requests
            var endpoint = context.GetEndpoint();
            if (endpoint == null || endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor>() == null)
            {
                await _next(context);
                return;
            }

            //extrude route from context
            var route = context.GetRouteData();
            if (route.Values.Count == 0)
            {
                throw new WinAuthExecutionException("Missing route configuration!");
            }

            //get auth manager
            _authManager = context.RequestServices.GetRequiredService<WinAuthManager>();

            //check session
            var validSessionId = await _authManager.IsSessionAliveAsync(context);

            //get access mode attribute
            var access = GetAccessMode(route);
            if(access is not { })
            {
                await _next(context);
                return;
            }

            //require unauthenticated
            if (!access.Auth)
            {
                if (!validSessionId)
                {
                    await _next(context);
                    return;
                }
                else
                {
                    if(_accessDeniedHandler is { })
                    {
                        await _accessDeniedHandler.RequireUnAuthenticated(context);
                    }
                    else
                    {
                        context.Response.StatusCode = 403;
                    }
                    return;
                }
            }

            //client does not pass valid session id
            //redirect to login
            if (!validSessionId)
            {
                if(_accessDeniedHandler is { })
                {
                    await _accessDeniedHandler.RequireAuthenticated(context);
                }
                else
                {
                    context.Response.StatusCode = 401;
                }

                return;
            }
            //client pass session id
            //go to destination page
            else
            {
                if (access.Role is null)
                {
                    await _next(context);
                    return;
                }
                else
                {
                    if (await _authManager.HasAccessAsync(context, access.Role))
                    {
                        await _next(context);
                        return;
                    }
                    else
                    {
                        if(_accessDeniedHandler is { })
                        {
                            var userRole = await _authManager.GetUserRole(context);
                            await _accessDeniedHandler.RequireRole(context, userRole?.ToString(), access.Role);
                        }
                        else
                        {
                            context.Response.StatusCode = 403;
                        }

                        return;
                    }
                }
            }
        }

        /// <summary>
        /// Get WinAuthAccesAttribute assigned with action base on route
        /// </summary>
        /// <param name="route">Route from HttpContext</param>
        /// <returns>Attribute object or null</returns>
        private WinAuthAuthorizeAttribute? GetAccessMode(RouteData route)
        {
            //get controller and action name
            var controllerName = route.Values["controller"];
            var actionName = route.Values["action"];

            if (controllerName is null || actionName is null)
            {
                return null;
            }

            //find controller
            var controller = _assembly.GetTypes()
                .FirstOrDefault(t => t.Name.Equals($"{controllerName}Controller"));

            //find action
            var action = controller?.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(t => t.Name == actionName!.ToString());

            //get access attribute
            var attribute = action?.GetCustomAttribute(typeof(WinAuthAuthorizeAttribute));
            
            //extrude access mode
            var access = (WinAuthAuthorizeAttribute?)attribute;

            return access;
        }
    }
}
