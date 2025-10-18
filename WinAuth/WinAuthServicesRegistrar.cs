using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace WinAuth
{
    public static class WinAuthServicesRegistrar
    {
        public static void AddWinAuth(this IServiceCollection services)
        {
            services.AddSingleton<WinAuthManager>();
        }

        public static void UseWinAuth(this WebApplication app)
        {
            app.UseMiddleware<WinAuthMiddleware>();
        }
    }
}
