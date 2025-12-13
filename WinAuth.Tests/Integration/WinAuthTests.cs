using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Net.Http.Headers;
using System.Net;

namespace WinAuth.Tests.Integration
{
    public class WinAuthTests
    {
        [Fact]
        public async Task NoSession_LoginPage_OK()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.GetAsync("/Home/Login");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NoSession_FreePage_OK()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.GetAsync("/Home/Index");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NoSession_NoAuthenticationRequired_OK()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.GetAsync("/Home/Login");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NoSession_AuthenticationRequired_RedirectToLogin()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            var response = await client.GetAsync("/Home/Page");

            response.Headers.TryGetValues("Location", out var location);

            Assert.Equal("/Home/Login", location!.First());
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        [Fact]
        public async Task NoSession_AuthenticationRequiredRoleRequired_RedirectToLogin()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            var response = await client.GetAsync("/Home/Admin");

            response.Headers.TryGetValues("Location", out var location);

            Assert.Equal("/Home/Login", location!.First());
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        [Fact]
        public async Task NoSessionPost_AuthenticationRequired_Unauthorized401()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.PostAsync("/Home/Page", null);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task NoSessionPost_AuthenticationRequiredRoleRequired_Unauthorized401()
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
        public async Task CreateSession_LoginSecondTime_Forbidden403()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var message = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"user", "test" },
                {"pass", "test" }
            });

            //login to get cookie
            var request = new HttpRequestMessage(HttpMethod.Post, "/Home/LoginUser")
            {
                Content = message
            };
            var response = await client.SendAsync(request);

            response.Headers.TryGetValues("Set-Cookie", out var cookies);
            var cookie = cookies!
                        .Select(c => SetCookieHeaderValue.Parse(c))
                        .FirstOrDefault(c => c.Name == "winauth_session_id");

            //second attempt with cookie
            request = new HttpRequestMessage(HttpMethod.Post, "/Home/LoginUser")
            {
                Content = message
            };
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task KillSession_LogoutWithValidSession_RedirectToHomePage()
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

            //login to get cookie
            var request = new HttpRequestMessage(HttpMethod.Post, "/Home/LoginUser")
            {
                Content = message
            };
            var response = await client.SendAsync(request);

            response.Headers.TryGetValues("Set-Cookie", out var cookies);
            var cookie = cookies!
                        .Select(c => SetCookieHeaderValue.Parse(c))
                        .FirstOrDefault(c => c.Name == "winauth_session_id");

            //logout
            request = new HttpRequestMessage(HttpMethod.Get, "/Home/Logout");
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);


            response.Headers.TryGetValues("Location", out var location);

            Assert.Equal("/", location!.First());
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        [Fact]
        public async Task KillSession_LogoutWithoutValidSession_RedirectToLogin()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            //logout
            var request = new HttpRequestMessage(HttpMethod.Get, "/Home/Logout");
            var response = await client.SendAsync(request);


            response.Headers.TryGetValues("Location", out var location);

            Assert.Equal("/Home/Login", location!.First());
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        [Fact]
        public async Task KillSession_LogoutWithValidSession_AccessPageAuthRequired_RedirectToLogin()
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
            
            Assert.NotNull(cookie);

            //logout
            request = new HttpRequestMessage(HttpMethod.Post, "/Home/Logout");
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            //test redirect to login
            response = await client.GetAsync("/Home/Page");

            response.Headers.TryGetValues("Location", out var location);

            Assert.Equal("/Home/Login", location!.First());
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        [Fact]
        public async Task Session_LoginPage_Forbidden403()
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

            Assert.NotNull(cookie);

            //login second time
            request = new HttpRequestMessage(HttpMethod.Get, "/Home/Login");
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        [Fact]
        public async Task Session_FreePage_OK()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient();

            var response = await client.GetAsync("/Home/Index");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }


        [Fact]
        public async Task Session_NoAuthenticationRequired_Forbidden403()
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

            Assert.NotNull(cookie);

            //login second time
            request = new HttpRequestMessage(HttpMethod.Get, "/Home/Login");
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            response.Headers.TryGetValues("Location", out var location);

            Assert.Equal("/Home/Forbidden", location!.First());
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        [Fact]
        public async Task Session_AuthenticationRequired_Ok()
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

            Assert.NotNull(cookie);

            //login second time
            request = new HttpRequestMessage(HttpMethod.Get, "/Home/Page");
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task Session_AuthenticationRequiredRoleRequired_Forbidden403()
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

            Assert.NotNull(cookie);

            //login second time
            request = new HttpRequestMessage(HttpMethod.Get, "/Home/Admin");
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            response.Headers.TryGetValues("Location", out var location);

            Assert.Equal("/Home/Forbidden", location!.First());
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        [Fact]
        public async Task SessionPost_AuthenticationRequired_OK()
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

            Assert.NotNull(cookie);
            
            var message2 = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"id", "1" },
            });
            request = new HttpRequestMessage(HttpMethod.Post, "/Home/Page")
            {
                Content = message
            };
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task SessionPost_AuthenticationRequiredRoleRequired_Forbidden403()
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

            Assert.NotNull(cookie);

            var message2 = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"name", "test" },
            });
            request = new HttpRequestMessage(HttpMethod.Post, "/Home/Admin")
            {
                Content = message
            };
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task SessionLowRolePost_AuthenticationRequiredRoleRequired_Forbidden403()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            var message = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"user", "user" },
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

            Assert.NotNull(cookie);

            var message2 = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"name", "test" },
            });
            request = new HttpRequestMessage(HttpMethod.Post, "/Home/Admin")
            {
                Content = message
            };
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task SessionHighRolePost_AuthenticationRequiredRoleRequired_OK()
        {
            var factory = new TestAppFactory();
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            var message = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"user", "admin" },
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

            Assert.NotNull(cookie);

            var message2 = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                {"name", "test" },
            });
            request = new HttpRequestMessage(HttpMethod.Post, "/Home/Admin")
            {
                Content = message
            };
            request.Headers.Add("Cookie", $"{cookie!.ToString};");
            response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }
}
