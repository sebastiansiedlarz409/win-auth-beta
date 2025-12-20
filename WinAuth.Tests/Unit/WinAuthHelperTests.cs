using Microsoft.AspNetCore.Routing;
using System.Reflection;
using WinAuth.Misc;

namespace WinAuth.Tests.Unit
{
    public class WinAuthHelperTests
    {
        [Fact]
        public void GetControllerActionAccessModeTest_AuthRequired_ReturnAttribute()
        {
            Assembly assembly = typeof(WinAuthHelperTests).Assembly;
            RouteData routeData = new RouteData();
            routeData.Values.Add("controller", "Test");
            routeData.Values.Add("action", "TestAction");

            var result = WinAuthHelper.GetControllerActionAccessMode(assembly, routeData);

            Assert.NotNull(result);
            Assert.True(result.Auth);
        }

        [Fact]
        public void GetControllerActionAccessModeTest_NoAuthRequired_ReturnAttribute()
        {
            Assembly assembly = typeof(WinAuthHelperTests).Assembly;
            RouteData routeData = new RouteData();
            routeData.Values.Add("controller", "Test");
            routeData.Values.Add("action", "TestAction2");

            var result = WinAuthHelper.GetControllerActionAccessMode(assembly, routeData);

            Assert.NotNull(result);
            Assert.False(result.Auth);
        }

        [Fact]
        public void GetControllerActionAccessModeTest_AuthRequiredWithRole_ReturnAttribute()
        {
            Assembly assembly = typeof(WinAuthHelperTests).Assembly;
            RouteData routeData = new RouteData();
            routeData.Values.Add("controller", "Test");
            routeData.Values.Add("action", "TestAction3");

            var result = WinAuthHelper.GetControllerActionAccessMode(assembly, routeData);

            Assert.NotNull(result);
            Assert.True(result.Auth);
            Assert.Equal("ADMIN", result.Role);
        }

        [Fact]
        public void GetControllerActionAccessModeTest_NoAttribute_ReturnNull()
        {
            Assembly assembly = typeof(WinAuthHelperTests).Assembly;
            RouteData routeData = new RouteData();
            routeData.Values.Add("controller", "Test");
            routeData.Values.Add("action", "TestAction4");

            var result = WinAuthHelper.GetControllerActionAccessMode(assembly, routeData);

            Assert.Null(result);
        }
    }
}
