using Microsoft.AspNetCore.Http;
using WinAuth.Wrappers;
using WinAuth.Exceptions;
using WinAuth.Session;

namespace WinAuth
{
    public sealed class WinAuthManager
    {
        private readonly string _domainName = string.Empty;
        private int _sessionLifeTime = 30;

        /// <summary>
        /// User can implement own session storage base on db, redis, memory or etc
        /// </summary>
        private readonly IWinAuthSessionStorage _sessionStorage;

        /// <summary>
        /// User can implement own role storage base on db, redis, memory or etc
        /// </summary>
        private readonly IWinAuthRoleProvider? _roleProvider;

        /// <summary>
        /// Wrapper over ASP.NET http context object
        /// </summary>
        private readonly IWinAuthHttpContextWrapper _contextWrapper;

        /// <summary>
        /// Wrapper over ASP.NET Directory Services
        /// </summary>
        private readonly IWinAuthCredentialValidator _credentialValidator;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="sessionStorage">Session storage implementation</param>
        /// <param name="domainName">Target domain name</param>
        /// <param name="liftime">Session life time in minutes</param>
        public WinAuthManager(IWinAuthHttpContextWrapper contextWrapper,
                              IWinAuthCredentialValidator credentialValidator,
                              IWinAuthSessionStorage sessionStorage,
                              IWinAuthRoleProvider? roleProvider,
                              string domainName,
                              int liftime)
        {
            _sessionStorage = sessionStorage;
            _credentialValidator = credentialValidator;
            _roleProvider = roleProvider;
            _contextWrapper = contextWrapper;

            _domainName = domainName;

            _sessionLifeTime = liftime;
            _credentialValidator = credentialValidator;
        }

        /// <summary>
        /// Check credentials in domain
        /// </summary>
        /// <param name="username">Domain user</param>
        /// <param name="password">Domain password</param>
        /// <returns>Valid or not</returns>
        public bool Login(string username, string password)
        {
            return _credentialValidator.CheckCredential(username, password, _domainName);
        }

        /// <summary>
        /// Create session, save it in storage, create cookie
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        /// <param name="userName">Username</param>
        /// <returns>Session Id as Guid</returns>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthSessionStorage fail</exception>
        public async Task<Guid?> CreateSessionAsync(HttpContext httpContext, string userName)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new WinAuthExecutionException($"Username must be provided for CreateSession!");
            }

            //create new session and store it
            var session = new WinAuthSession(userName, _sessionLifeTime);

            try
            {
                await _sessionStorage.StoreSessionAsync(session).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new WinAuthExecutionException($"Store session procedure failed! Check inner exception!", ex);
            }

            SetCookie(httpContext, session);

            //return session id
            return session.SessionId;
        }

        /// <summary>
        /// Remove session from storage
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthSessionStorage fail</exception>
        public async Task KillSessionAsync(HttpContext httpContext)
        {
            var session = await GetSessionFromContextAsync(httpContext).ConfigureAwait(false);

            //if session exist inside session storage remove it
            if (session is { })
            {
                try
                {
                    await _sessionStorage.RemoveSessionAsync(session).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    throw new WinAuthExecutionException($"Remove session procedure failed! Check inner exception!", ex);
                }
            }
        }

        /// <summary>
        /// Check session storage contains session
        /// Checks session liftime
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        /// <returns>Valid session</returns>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthSessionStorage or IWinAuthRoleProvider fail</exception>
        public async Task<bool> IsSessionAliveAsync(HttpContext httpContext)
        {
            var session = await GetSessionFromContextAsync(httpContext).ConfigureAwait(false);

            if (session is null)
            {
                return false;
            }
            
            //if session exist in storage check liftime
            bool validLifeTime = session.ExpirationDate >= DateTime.UtcNow;

            if (validLifeTime)
            {
                //setup role
                if(_roleProvider is { })
                {
                    string? role = null;
                    try
                    {
                        role = await _roleProvider.GetRoleAsync(session).ConfigureAwait(false);

                        session.Role = role;
                    }
                    catch(Exception ex)
                    {
                        throw new WinAuthExecutionException($"Get role procedure failed! Check inner exception!", ex);
                    }
                }

                //rewrite session
                //not every time due to perfomance of session manager
                if (session.ExpirationDate - DateTime.Now < TimeSpan.FromMinutes(2))
                {
                    session.ExpirationDate.AddMinutes(_sessionLifeTime);

                    try
                    {
                        await _sessionStorage.UpdateSessionAsync(session).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        throw new WinAuthExecutionException($"Update session procedure failed! Check inner exception!", ex);
                    }
                    SetCookie(httpContext, session);
                }
            }

            return validLifeTime;
        }

        /// <summary>
        /// Check if user is logged in
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        /// <returns>True if user is logged in</returns>
        public async Task<bool> IsAuthenticated(HttpContext httpContext)
        {
            var session = await GetSessionFromContextAsync(httpContext).ConfigureAwait(false);

            if (session is null) return false;

            return session.ExpirationDate >= DateTime.UtcNow;
        }

        /// <summary>
        /// Return current user username
        /// </summary>
        /// <param name="httpContext">HTTP context object</param>
        /// <returns>Currnent user username or null</returns>
        public async Task<string?> GetUserName(HttpContext httpContext)
        {
            var session = await GetSessionFromContextAsync(httpContext).ConfigureAwait(false);

            return session?.UserName;
        }

        /// <summary>
        /// Return current user role name
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        /// <returns>Current user role name as string or null</returns>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthRoleProvider fail</exception>
        public async Task<object?> GetUserRole(HttpContext httpContext)
        {
            //if there is no role system
            //every logged user has access to everything
            if (_roleProvider is null)
            {
                return null;
            }

            var session = await GetSessionFromContextAsync(httpContext).ConfigureAwait(false);

            return session?.Role;
        }

        /// <summary>
        /// Checks whether the assigned role is sufficient to gain access by calling IWinAuthRoleProvider implementation
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        /// <param name="role">Minimal role to gain access</param>
        /// <returns>True if access is permitted</returns>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthRoleProvider fail</exception>
        public async Task<bool> HasAccessAsync(HttpContext httpContext, string role)
        {
            //if there is no role system
            //every logged user has access to everything
            if(_roleProvider is null)
            {
                return true;
            }

            var session = await GetSessionFromContextAsync(httpContext).ConfigureAwait(false);

            if (session is not { })
            {
                return false;
            }

            try
            {
                return await _roleProvider.HasAccessAsync(session, role).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new WinAuthExecutionException($"Has access procedure failed! Check inner exception!", ex);
            }
        }

        private async Task<WinAuthSession?> GetSessionFromContextAsync(HttpContext httpContext)
        {
            //session id
            var sessionId = _contextWrapper.GetCookieValue(httpContext, "winauth_session_id");

            //check session id
            if (sessionId is not { })
            {
                return null;
            }

            var sid = new Guid(sessionId);
            WinAuthSession? session = null;
            try
            {
                session = await _sessionStorage.GetSessionAsync(sid).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new WinAuthExecutionException($"Get session procedure failed! Check inner exception!", ex);
            }

            return session;
        }
        
        private void SetCookie(HttpContext httpContext, WinAuthSession session)
        {
            _contextWrapper.SetHttpCookie(httpContext, "winauth_session_id", session.SessionId.ToString(), session.ExpirationDate);
        }
    }
}
