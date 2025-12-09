using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using WinAuth.Wrappers;

namespace WinAuth.Tests.Integration
{
    public class TestAppFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                var descriptor = services.FirstOrDefault(s => s.ServiceType == typeof(IWinAuthCredentialValidator));
                if(descriptor is { })
                {
                    services.Remove(descriptor);
                }

                var descriptor2 = services.FirstOrDefault(s => s.ServiceType == typeof(IWinAuthHttpContextWrapper));
                if(descriptor2 is { })
                {
                    services.Remove(descriptor2);
                }

                services.AddSingleton<IWinAuthCredentialValidator, WinAuthTestCredentialValidator>();
                services.AddSingleton<IWinAuthHttpContextWrapper, WinAuthTestHttpContextWrapper>();
            });
        }
    }

}
