using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Reflection;
using WinAuth.Attributes;

namespace WinAuth
{
    public class WinAuthMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly WinAuthManager _authManager;

        public WinAuthMiddleware(RequestDelegate next, WinAuthManager authManager)
        {
            _next = next;
            _authManager = authManager;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (Path.HasExtension(context.Request.Path))
            {
                await _next(context);
                return;
            }

            var route = context.GetRouteData();

            if(route.Values.Count == 0)
            {
                await _next(context);
                return;
            }

            var access = GetAccessMode(route);
            if(access is not { })
            {
                await _next(context);
                return;
            }

            //session id
            var sessionId = context.Request.Cookies
                                .FirstOrDefault(t => t.Key == "winauth_session_id").Value;

            var validSessionId = _authManager.IsSessionAlive(sessionId);

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
                    context.Response.Redirect("/Home/Index", false);
                    return;
                }
            }
            else
            {
                //client does not pass valid session id
                //redirect to login
                if (!validSessionId)
                {
                    context.Response.Redirect("/Home/Login", false);
                    return;
                }
                //client pass session id
                //go to destination page
                else
                {
                    await _next(context);
                    return;
                }
            }
        }

        private WinAuthAccessAttribute? GetAccessMode(RouteData route)
        {
            var controllerName = route.Values["controller"];
            var actionName = route.Values["action"];

            var controller = Assembly.GetEntryAssembly()
                .GetTypes().FirstOrDefault(t => t.Name.Contains($"{controllerName}Controller"));

            //if controller is null led other middleware handle it
            if (controller is not { })
            {
                return null;
            }

            //actions are public
            var action = controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(t => t.Name == actionName.ToString());

            //double check
            if (action is not { })
            {
                return null;
            }

            var attribute = action.GetCustomAttribute(typeof(WinAuthAccessAttribute));

            //double check
            if (attribute is not { })
            {
                return null;
            }

            var access = (WinAuthAccessAttribute)attribute;

            return access;
        }
    }
}
