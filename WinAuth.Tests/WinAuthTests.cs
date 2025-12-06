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
                .Setup(t => t.StoreSession(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {

                });

            var credentialValidator = new Mock<ICredentialValidator>();

            var httpContext = new DefaultHttpContext();
            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var guid = authManager.CreateSession(httpContext, "testomir.testowski");

            Assert.NotNull(guid);
        }

        [Fact]
        public void CreateSessionTest_SaveSessionThrow()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.SetHttpCookie(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>()))
                .Callback(() => {

                });

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.StoreSession(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            Assert.Throws<WinAuthExecutionException>(() =>
            {
                var guid = authManager.CreateSession(new DefaultHttpContext(), "testomir.testowski");
            });
        }

        [Fact]
        public void CreateSessionTest_NoUserName()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.SetHttpCookie(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>()))
                .Callback(() => {

                });

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.StoreSession(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {

                });

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            Assert.Throws<WinAuthExecutionException>(() =>
            {
                var guid = authManager.CreateSession(new DefaultHttpContext(), "");
            });
        }

        [Fact]
        public void KillSession_BasicScenario()
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
                .Setup(t => t.GetSession(guid)).Returns(session);
            sessionStorage
                .Setup(t => t.RemoveSession(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {

                });

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            authManager.KillSession(new DefaultHttpContext());
        }

        [Fact]
        public void KillSession_RemoveSessionThrow()
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
                .Setup(t => t.GetSession(guid)).Returns(session);
            sessionStorage
                .Setup(t => t.RemoveSession(It.IsAny<WinAuthSession>()))
                .Callback(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            Assert.Throws<WinAuthExecutionException>(() =>
            {
                authManager.KillSession(new DefaultHttpContext());
            });
        }

        [Fact]
        public void IsSessionAlive_BasicScenario_ValidSession()
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
                .Setup(t => t.GetSession(guid)).Returns(session);

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = authManager.IsSessionAlive(new DefaultHttpContext());

            Assert.True(valid);
        }

        [Fact]
        public void IsSessionAlive_BasicScenario_NotValidSession()
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
                .Setup(t => t.GetSession(guid)).Returns(session);

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = authManager.IsSessionAlive(new DefaultHttpContext());

            Assert.False(valid);
        }

        [Fact]
        public void IsSessionAlive_BasicScenario_NoCookie()
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
                .Setup(t => t.GetSession(guid)).Returns(session);
            
            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = authManager.IsSessionAlive(new DefaultHttpContext());

            Assert.False(valid);
        }

        [Fact]
        public void IsSessionAlive_BasicScenario_CookieWithoutSession()
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
                .Setup(t => t.GetSession(guid)).Returns((WinAuthSession?)null);

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = authManager.IsSessionAlive(new DefaultHttpContext());

            Assert.False(valid);
        }

        [Fact]
        public void IsSessionAlive_GetSessionThrow()
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
                .Setup(t => t.GetSession(guid))
                .Callback(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            Assert.Throws<WinAuthExecutionException>(() =>
            {
                bool valid = authManager.IsSessionAlive(new DefaultHttpContext());
            });
        }

        [Fact]
        public void IsAuthenticated_Auhenticated()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper.Setup(t=>t.IsAuthenticated(It.IsAny<HttpContext>())).Returns(true);

            var sessionStorage = new Mock<IWinAuthSessionStorage>();

            var credentialValidator = new Mock<ICredentialValidator>();

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

            var credentialValidator = new Mock<ICredentialValidator>();

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

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var username = authManager.UserName(new DefaultHttpContext());

            Assert.Equal("testomir.testowski", username);
        }

        [Fact]
        public void UserRole_BasicScenario()
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
                .Setup(t => t.GetSession(guid)).Returns(session);

            var roleProvider = new Mock<IWinAuthRoleProvider>();
            roleProvider.Setup(t => t.GetRole(session)).Returns("ADMIN");
            
            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            var role = authManager.UserRole(new DefaultHttpContext());

            Assert.Equal("ADMIN", role!.ToString());
        }

        [Fact]
        public void UserRole_BasicScenario_NoProvider()
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
                .Setup(t => t.GetSession(guid)).Returns(session);

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var role = authManager.UserRole(new DefaultHttpContext());

            Assert.Null(role);
        }

        [Fact]
        public void UserRole_BasicScenario_ProviderThrow()
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
                .Setup(t => t.GetSession(guid)).Returns(session);

            var roleProvider = new Mock<IWinAuthRoleProvider>();
            roleProvider
                .Setup(t => t.GetRole(session))
                .Returns(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            Assert.Throws<WinAuthExecutionException>(() =>
            {
                var role = authManager.UserRole(new DefaultHttpContext());
            });
        }

        [Fact]
        public void HasAccess_BasicScenario()
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
                .Setup(t => t.GetSession(guid)).Returns(session);

            var roleProvider = new Mock<IWinAuthRoleProvider>();
            roleProvider.Setup(t => t.HasAccess(session, "USER")).Returns(true);

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            var permission = authManager.HasAccess(new DefaultHttpContext(), "USER");

            Assert.True(permission);
        }

        [Fact]
        public void HasAccess_BasicScenario_NoProvider()
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
                .Setup(t => t.GetSession(guid)).Returns(session);

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var permission = authManager.HasAccess(new DefaultHttpContext(), "USER");

            Assert.True(permission);
        }

        [Fact]
        public void HasAccess_BasicScenario_ProviderThrow()
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
                .Setup(t => t.GetSession(guid)).Returns(session);


            var roleProvider = new Mock<IWinAuthRoleProvider>();
            roleProvider
                .Setup(t => t.HasAccess(session, "USER"))
                .Returns(() =>
                {
                    throw new Exception();
                });

            var credentialValidator = new Mock<ICredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            Assert.Throws<WinAuthExecutionException>(() =>
            {
                var permission = authManager.HasAccess(new DefaultHttpContext(), "USER");
            });
        }
    }
}
