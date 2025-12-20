using Microsoft.AspNetCore.Routing;
using System.Reflection;
using WinAuth.Attributes;

namespace WinAuth.Misc
{
    internal static class WinAuthHelper
    {
        /// <summary>
        /// Get WinAuthAccesAttribute assigned with action base on route
        /// </summary>
        /// <param name="route">Route from HttpContext</param>
        /// <returns>Attribute object or null</returns>
        public static WinAuthAuthorizeAttribute? GetControllerActionAccessMode(Assembly assembly, RouteData route)
        {
            //get controller and action name
            var controllerName = route.Values["controller"];
            var actionName = route.Values["action"];

            if (controllerName is null || actionName is null)
            {
                return null;
            }

            //find controller
            var controller = assembly.GetTypes()
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
