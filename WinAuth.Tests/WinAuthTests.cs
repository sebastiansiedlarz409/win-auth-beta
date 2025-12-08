using Microsoft.AspNetCore.Http;
using Moq;
using WinAuth.Exceptions;
using WinAuth.Session;

namespace WinAuth.Tests
{
    public class WinAuthTests
    {
        [Fact]
        public void CreateSessionTest_BasicScenario()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.SetHttpCookie(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>()))
                .Callback(() => {

                });
            
            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.StoreSessionAsync(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {

                });

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var httpContext = new DefaultHttpContext();
            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var guid = authManager.CreateSessionAsync(httpContext, "testomir.testowski");

            Assert.NotNull(guid);
        }

        [Fact]
        public async Task CreateSessionTest_SaveSessionThrow()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.SetHttpCookie(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>()))
                .Callback(() => {

                });

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.StoreSessionAsync(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            await Assert.ThrowsAsync<WinAuthExecutionException>(async () =>
            {
                await authManager.CreateSessionAsync(new DefaultHttpContext(), "testomir.testowski");
            });
        }

        [Fact]
        public async Task CreateSessionTest_NoUserName()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.SetHttpCookie(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>()))
                .Callback(() => {

                });

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.StoreSessionAsync(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {

                });

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            await Assert.ThrowsAsync<WinAuthExecutionException>(async () =>
            {
                await authManager.CreateSessionAsync(new DefaultHttpContext(), "");
            });
        }

        [Fact]
        public async Task KillSession_BasicScenario()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);
            sessionStorage
                .Setup(t => t.RemoveSessionAsync(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {

                });

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            await authManager.KillSessionAsync(new DefaultHttpContext());
        }

        [Fact]
        public async Task KillSession_RemoveSessionThrow()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);
            sessionStorage
                .Setup(t => t.RemoveSessionAsync(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            await Assert.ThrowsAsync<WinAuthExecutionException>(async () =>
            {
                await authManager.KillSessionAsync(new DefaultHttpContext());
            });
        }

        [Fact]
        public async Task IsSessionAlive_BasicScenario_ValidSession()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = await authManager.IsSessionAliveAsync(new DefaultHttpContext());

            Assert.True(valid);
        }

        [Fact]
        public async Task IsSessionAlive_BasicScenario_NotValidSession()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = await authManager.IsSessionAliveAsync(new DefaultHttpContext());

            Assert.False(valid);
        }

        [Fact]
        public async Task IsSessionAlive_BasicScenario_NoCookie()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns((string?)null);

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);
            
            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = await authManager.IsSessionAliveAsync(new DefaultHttpContext());

            Assert.False(valid);
        }

        [Fact]
        public async Task IsSessionAlive_BasicScenario_CookieWithoutSession()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult((WinAuthSession?)null));

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = await authManager.IsSessionAliveAsync(new DefaultHttpContext());

            Assert.False(valid);
        }

        [Fact]
        public async Task IsSessionAlive_GetSessionThrow()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid))
                .Callback(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            await Assert.ThrowsAsync<WinAuthExecutionException>(async () =>
            {
                await authManager.IsSessionAliveAsync(new DefaultHttpContext());
            });
        }

        [Fact]
        public void IsAuthenticated_Auhenticated()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper.Setup(t=>t.IsAuthenticated(It.IsAny<HttpContext>())).Returns(true);

            var sessionStorage = new Mock<IWinAuthSessionStorage>();

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = authManager.IsAuthenticated(new DefaultHttpContext());

            Assert.True(valid);
        }

        [Fact]
        public void IsAuthenticated_NotAuhenticated()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper.Setup(t => t.IsAuthenticated(It.IsAny<HttpContext>())).Returns(false);

            var sessionStorage = new Mock<IWinAuthSessionStorage>();

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = authManager.IsAuthenticated(new DefaultHttpContext());

            Assert.False(valid);
        }

        [Fact]
        public void IsAuthenticated_UserName()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper.Setup(t => t.GetUserName(It.IsAny<HttpContext>())).Returns("testomir.testowski");

            var sessionStorage = new Mock<IWinAuthSessionStorage>();

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var username = authManager.UserName(new DefaultHttpContext());

            Assert.Equal("testomir.testowski", username);
        }

        [Fact]
        public async Task UserRole_BasicScenario()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);

            var roleProvider = new Mock<IWinAuthRoleProvider>();
            roleProvider.Setup(t => t.GetRoleAsync(session)).Returns(Task.FromResult("ADMIN")!);
            
            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            var role =  await authManager.UserRole(new DefaultHttpContext());

            Assert.Equal("ADMIN", role!.ToString());
        }

        [Fact]
        public async Task UserRole_BasicScenario_NoProvider()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var role = await authManager.UserRole(new DefaultHttpContext());

            Assert.Null(role);
        }

        [Fact]
        public async Task UserRole_BasicScenario_ProviderThrow()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);

            var roleProvider = new Mock<IWinAuthRoleProvider>();
            roleProvider
                .Setup(t => t.GetRoleAsync(session))
                .Returns(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            await Assert.ThrowsAsync<WinAuthExecutionException>(async () =>
            {
                await authManager.UserRole(new DefaultHttpContext());
            });
        }

        [Fact]
        public async Task HasAccess_BasicScenario()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);

            var roleProvider = new Mock<IWinAuthRoleProvider>();
            roleProvider.Setup(t => t.HasAccessAsync(session, "USER")).Returns(Task.FromResult(true)!);

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            var permission = await authManager.HasAccessAsync(new DefaultHttpContext(), "USER");

            Assert.True(permission);
        }

        [Fact]
        public async Task HasAccess_BasicScenario_NoProvider()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var permission = await authManager.HasAccessAsync(new DefaultHttpContext(), "USER");

            Assert.True(permission);
        }

        [Fact]
        public async Task HasAccess_BasicScenario_ProviderThrow()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);


            var roleProvider = new Mock<IWinAuthRoleProvider>();
            roleProvider
                .Setup(t => t.HasAccessAsync(session, "USER"))
                .Returns(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            await Assert.ThrowsAsync<WinAuthExecutionException>(async () =>
            {
                await authManager.HasAccessAsync(new DefaultHttpContext(), "USER");
            });
        }
    }
}
