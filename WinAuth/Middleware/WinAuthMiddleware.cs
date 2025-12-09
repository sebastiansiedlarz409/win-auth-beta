using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Reflection;
using WinAuth.Attributes;
using WinAuth.Exceptions;
using WinAuth.Session;

namespace WinAuth.Middleware
{
    public sealed class WinAuthMiddleware
    {
        private readonly RequestDelegate _next;

        private readonly WinAuthManager _authManager;
        private readonly IWinAuthAccessDeniedHandler? _accessDeniedHandler;

        private readonly Assembly _assembly;

        public WinAuthMiddleware(RequestDelegate next,
                                 WinAuthManager authManager,
                                 Assembly assembly,
                                 IWinAuthAccessDeniedHandler? accessDeniedHandler = null)
        {
            _next = next;

            _authManager = authManager;
            _accessDeniedHandler = accessDeniedHandler;

            _assembly = assembly;
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

            //if there is no route
            //route middleware wasnt registered before this middleware
            //skip auth validation
            if (route.Values.Count == 0)
            {
                throw new WinAuthExecutionException("Missing route configuration!");
            }

            //check if session exist
            //if exists checks if its alive as well
            var validSessionId = await _authManager.IsSessionAliveAsync(context);

            //get access mode attribute
            var access = GetAccessMode(route);
            if(access is not { })
            {
                await _next(context);
                return;
            }

            //client does not pass valid session id
            //redirect to login
            if (!validSessionId)
            {
                if(_accessDeniedHandler is { })
                {
                    await _accessDeniedHandler.OnSessionExpired(context);
                }
                else
                    context.Response.StatusCode = 401;

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
                            await _accessDeniedHandler.OnRoleNotHighEnough(context);
                        }
                        else
                            context.Response.StatusCode = 403;

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

            //scan provided assembly
            var controller = _assembly.GetTypes()
                .FirstOrDefault(t => t.Name.Contains($"{controllerName}Controller"));

            //if controller is null led other middleware handle it
            if (controller is null)
            {
                return null;
            }

            //actions are public
            //actionName cant be null if routing is used before this middlware
            var action = controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(t => t.Name == actionName!.ToString());

            //double check
            if (action is null)
            {
                return null;
            }

            //get access attribute
            var attribute = action.GetCustomAttribute(typeof(WinAuthAuthorizeAttribute));

            //double check
            if (attribute is null)
            {
                return null;
            }
            
            //extrude access mode
            var access = (WinAuthAuthorizeAttribute)attribute;

            return access;
        }
    }
}
