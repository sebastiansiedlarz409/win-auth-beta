using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Net.Http.Headers;
using System.Net;

namespace WinAuth.Tests.Integration
{
    public class WinAuthTests
    {
        [Fact]
        public async Task NoSession_GetFreeEndpoint_OK()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.GetAsync("/Home/Index");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NoSession_GetAuthorizeEndpoint_OK_LoginPage()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.GetAsync("/Home/Page");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NoSession_GetAuthorizeWithRoleEndpoint_OK_LoginPage()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.GetAsync("/Home/Admin");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NoSession_PostAuthorizeEndpoint_Unauthorized()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.PostAsync("/Home/Admin", null);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task CreateSession_Login_ReturnCookie()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var message = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"user", "test" },
                {"pass", "test" }
            });
            var response = await client.PostAsync("/Home/LoginUser", message);

            response.Headers.TryGetValues("Set-Cookie", out var cookies);
            var cookie = cookies!
                        .Select(c => SetCookieHeaderValue.Parse(c))
                        .FirstOrDefault(c => c.Name == "winauth_session_id");

            Assert.NotNull(cookie);
        }

        [Fact]
        public async Task CreateSession_LoginSecondTime_ReturnCookie()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            var message = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"user", "test" },
                {"pass", "test" }
            });

            //login
            var request = new HttpRequestMessage(HttpMethod.Post, "/Home/LoginUser")
            {
                Content = message
            };
            var response = await client.SendAsync(request);

            response.Headers.TryGetValues("Set-Cookie", out var cookies);
            var cookie = cookies!
                        .Select(c => SetCookieHeaderValue.Parse(c))
                        .FirstOrDefault(c => c.Name == "winauth_session_id");

            //second attempt
            request = new HttpRequestMessage(HttpMethod.Post, "/Home/LoginUser")
            {
                Content = message
            };
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            response.Headers.TryGetValues("Location", out var location);

            Assert.Equal("/Home/Page", location!.First());
        }
    }
}
