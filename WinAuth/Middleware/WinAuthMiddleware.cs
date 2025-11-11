using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Reflection;
using WinAuth.Attributes;

namespace WinAuth.Middleware
{
    public sealed class WinAuthMiddleware
    {
        private readonly RequestDelegate _next;

        private readonly WinAuthManager _authManager;
        private readonly Assembly _assembly;

        private string _loginRoute;
        private string _forbiddenRoute;

        public WinAuthMiddleware(RequestDelegate next, WinAuthManager authManager, Assembly assembly, string loginRoute, string forbiddenRoute)
        {
            _next = next;

            _authManager = authManager;
            _assembly = assembly;
            _loginRoute = loginRoute;
            _forbiddenRoute = forbiddenRoute;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            //skip validation for resources files like css or js
            if (Path.HasExtension(context.Request.Path))
            {
                await _next(context);
                return;
            }

            //extrude route from context
            var route = context.GetRouteData();

            //if there is no route
            //route middleware wasnt registered before this middleware
            //skip auth validation
            if(route.Values.Count == 0)
            {
                await _next(context);
                return;
            }

            //check if session exist
            //if exists checks if its alive as well
            var validSessionId = _authManager.IsSessionAlive(context);

            //get access mode attribute
            var access = GetAccessMode(route);
            if(access is not { })
            {
                await _next(context);
                return;
            }

            if (access.Access == WinAuthAccess.Login)
            {
                //client does not pass valid session id
                //pass to login is allowed
                if (!validSessionId) 
                {
                    await _next(context);
                    return;
                }
                //client pass valid session id
                //pass to login is not allowed
                else
                {
                    context.Response.Redirect("/", false);
                    return;
                }
            }
            else
            {
                //client does not pass valid session id
                //redirect to login
                if (!validSessionId)
                {
                    context.Response.Redirect(_loginRoute, false);
                    return;
                }
                //client pass session id
                //go to destination page
                else
                {
                    if(access.Role is null)
                    {
                        await _next(context);
                        return;
                    }
                    else
                    {
                        if (_authManager.HasAccess(context, access.Role))
                        {
                            await _next(context);
                            return;
                        }
                        else
                        {
                            context.Response.Redirect(_forbiddenRoute, false);
                            return;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Get WinAuthAccesAttribute assigned with action base on route
        /// </summary>
        /// <param name="route">Route from HttpContext</param>
        /// <returns>Attribute object or null</returns>
        private WinAuthAccessAttribute? GetAccessMode(RouteData route)
        {
            //get controller and action name
            var controllerName = route.Values["controller"];
            var actionName = route.Values["action"];

            //scan provided assembly
            var controller = _assembly.GetTypes()
                .FirstOrDefault(t => t.Name.Contains($"{controllerName}Controller"));

            //if controller is null led other middleware handle it
            if (controller is not { })
            {
                return null;
            }

            //actions are public
            //actionName cant be null if routing is used before this middlware
            var action = controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(t => t.Name == actionName!.ToString());

            //double check
            if (action is not { })
            {
                return null;
            }

            //get access attribute
            var attribute = action.GetCustomAttribute(typeof(WinAuthAccessAttribute));

            //double check
            if (attribute is not { })
            {
                return null;
            }
            
            //extrude access mode
            var access = (WinAuthAccessAttribute)attribute;

            return access;
        }
    }
}
