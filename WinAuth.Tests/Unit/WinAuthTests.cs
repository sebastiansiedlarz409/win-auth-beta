using Microsoft.AspNetCore.Http;
using Moq;
using WinAuth.Wrappers;
using WinAuth.Exceptions;
using WinAuth.Session;

namespace WinAuth.Tests.Unit
{
    public class WinAuthTests
    {
        [Fact]
        public void CreateSessionTest_CreateSession_CheckReturnedGuid()
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
        public async Task CreateSessionTest_SaveSessionThrow_CheckThrow()
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
        public async Task CreateSessionTest_NoUserNameProvided_CheckThrow()
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
        public async Task KillSession_RemoveSession_CheckNoThrow()
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
        public async Task KillSession_RemoveSessionThrow_CheckThrow()
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
        public async Task IsSessionAlive_ValidSession_CheckIfValid()
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
        public async Task IsSessionAlive_NotValidSession_CheckIfNotValid()
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
        public async Task IsSessionAlive_NoCookieProvided_CheckIfNotValid()
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
            
            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            bool valid = await authManager.IsSessionAliveAsync(new DefaultHttpContext());

            Assert.False(valid);
        }

        [Fact]
        public async Task IsSessionAlive_CookieNoSessionInStorage_CheckIfNotValid()
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
        public async Task IsSessionAlive_GetSessionThrow_CheckIfThrow()
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
        public void IsAuthenticated_Authenticated_CheckIfValid()
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
        public void IsAuthenticated_NotAuthenticated_CheckIfNotValid()
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
        public void IsAuthenticated_SuccessfullAuth_CheckUserName()
        {
            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper.Setup(t => t.GetUserName(It.IsAny<HttpContext>())).Returns("testomir.testowski");

            var sessionStorage = new Mock<IWinAuthSessionStorage>();

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, null, "test.local", 30);

            var username = authManager.GetUserName(new DefaultHttpContext());

            Assert.Equal("testomir.testowski", username);
        }

        [Fact]
        public async Task UserRole_RoleManager_CheckReturnedRole()
        {
            var guid = Guid.NewGuid();
            var session = new WinAuthSession("testomir.testowski", 30);
            session.SessionId = guid;
            session.ExpirationDate = DateTime.UtcNow.AddMinutes(-30);
            session.Role = "ADMIN";

            var httpContextWrapper = new Mock<IWinAuthHttpContextWrapper>();
            httpContextWrapper
                .Setup(t => t.GetCookieValue(It.IsAny<HttpContext>(), "winauth_session_id"))
                .Returns(guid.ToString());

            var sessionStorage = new Mock<IWinAuthSessionStorage>();
            sessionStorage
                .Setup(t => t.GetSessionAsync(guid)).Returns(Task.FromResult(session)!);

            var roleProvider = new Mock<IWinAuthRoleProvider>();
            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            var role =  await authManager.GetUserRole(new DefaultHttpContext());

            Assert.Equal("ADMIN", role!.ToString());
        }

        [Fact]
        public async Task UserRole_NoProvider_CheckIfThrow()
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

            var role = await authManager.GetUserRole(new DefaultHttpContext());

            Assert.Null(role);
        }

        [Fact]
        public async Task HasAccess_ValidRole_Permitted()
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
        public async Task HasAccess_NotValidRole_Denied()
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
            roleProvider.Setup(t => t.HasAccessAsync(session, "USER")).Returns(Task.FromResult(false)!);

            var credentialValidator = new Mock<IWinAuthCredentialValidator>();

            var authManager = new WinAuthManager(httpContextWrapper.Object, credentialValidator.Object, sessionStorage.Object, roleProvider.Object, "test.local", 30);

            var permission = await authManager.HasAccessAsync(new DefaultHttpContext(), "USER");

            Assert.False(permission);
        }

        [Fact]
        public async Task HasAccess_NoProvider_Permitted()
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
        public async Task HasAccess_ProviderThrow_CheckIfThrow()
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
