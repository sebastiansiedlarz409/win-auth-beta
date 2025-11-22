using Microsoft.AspNetCore.Http;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
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
        private readonly IWinAuthSessionStorage _sessionManager;

        /// <summary>
        /// User can implement own role storage base on db, redis, memory or etc
        /// </summary>
        private readonly IWinAuthRoleProvider? _roleProvider;

        /// <summary>
        /// Wrapper over ASP.NET http context object
        /// </summary>
        private readonly WinAuthHttpContextWrapper _contextWrapper;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="sessionManager">Session storage implementation</param>
        /// <param name="domainName">Target domain name</param>
        /// <param name="liftime">Session life time in minutes</param>
        public WinAuthManager(WinAuthHttpContextWrapper contextWrapper,
                              IWinAuthSessionStorage sessionManager,
                              IWinAuthRoleProvider? roleProvider,
                              string domainName,
                              int liftime)
        {
            _sessionManager = sessionManager;
            _roleProvider = roleProvider;
            _contextWrapper = contextWrapper;

            _domainName = domainName;

            _sessionLifeTime = liftime;
        }

        /// <summary>
        /// Check credentials in domain
        /// </summary>
        /// <param name="username">Domain user</param>
        /// <param name="password">Domain password</param>
        /// <returns>Valid or not</returns>
        public bool Login(string username, string password)
        {
            using var context = new PrincipalContext(ContextType.Domain, _domainName);

            var valid = context.ValidateCredentials(username, password);

            return valid;
        }

        /// <summary>
        /// Create session, save it in storage, create cookie
        /// </summary>
        /// <param name="httpContext">HTTP Context Object</param>
        /// <param name="userName">Username</param>
        /// <returns>Session Id as Guid</returns>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthSessionStorage fail</exception>
        public Guid CreateSession(HttpContext httpContext, string userName)
        {
            //create new session and store it
            var session = new WinAuthSession(userName, _sessionLifeTime);

            try
            {
                _sessionManager.StoreSession(session);
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
        public void KillSession(HttpContext httpContext)
        {
            var session = GetSessionFromContext(httpContext);

            //if session exist inside session storage remove it
            if (session is { })
            {
                try
                {
                    _sessionManager.RemoveSession(session);
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
        public bool IsSessionAlive(HttpContext httpContext)
        {
            var session = GetSessionFromContext(httpContext);

            if (session is not { })
            {
                return false;
            }
            
            //if session exist in storage check liftime
            bool validLifeTime = session.ExpirationDate >= DateTime.UtcNow;

            if (validLifeTime)
            {
                //setup user data for app purposes
                var claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.Name, session.UserName));

                //setup role
                if(_roleProvider is { })
                {
                    string? role = null;
                    try
                    {
                        role = _roleProvider.GetRole(session);
                    }
                    catch(Exception ex)
                    {
                        throw new WinAuthExecutionException($"Get role procedure failed! Check inner exception!", ex);
                    }

                    if (role is { })
                    {
                        claims.Add(new Claim(ClaimTypes.Role, role!));
                    }
                }

                var identity = new ClaimsIdentity(claims, "WinAuth");
                var principal = new ClaimsPrincipal(identity);

                httpContext.User = principal;

                //rewrite session
                //not every time due to perfomance of session manager
                if (session.ExpirationDate - DateTime.Now < TimeSpan.FromMinutes(2))
                {
                    session.ExpirationDate.AddMinutes(_sessionLifeTime);

                    try
                    {
                        _sessionManager.UpdateSession(session);
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
        /// <param name="httpContext">HTTP context object</param>
        /// <returns>True if user is logged in</returns>
        public bool IsAuthenticated(HttpContext httpContext)
        {
            return _contextWrapper.IsAuthenticated(httpContext);
        }

        /// <summary>
        /// Return user name
        /// </summary>
        /// <param name="httpContext">HTTP context object</param>
        /// <returns>Username or null</returns>
        public string? UserName(HttpContext httpContext)
        {
            return _contextWrapper.GetUserName(httpContext);
        }

        /// <summary>
        /// Return role name
        /// </summary>
        /// <param name="httpContext">HTTP context object</param>
        /// <returns>Role name</returns>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthRoleProvider fail</exception>
        public object? UserRole(HttpContext httpContext)
        {
            //if there is no role system
            //every logged user has access to everything
            if (_roleProvider is null)
            {
                return null;
            }

            var session = GetSessionFromContext(httpContext);

            if (session is not { })
            {
                return null;
            }

            try
            {
                return _roleProvider.GetRole(session);
            }
            catch (Exception ex)
            {
                throw new WinAuthExecutionException($"Get session procedure failed! Check inner exception!", ex);
            }
        }

        /// <summary>
        /// Check if provided role is high enough
        /// base on IWinAuthRoleProvider implementation
        /// </summary>
        /// <param name="httpContext">HTTP context object</param>
        /// <param name="role">Minimal role for access</param>
        /// <returns>True if access is permitted</returns>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthRoleProvider fail</exception>
        public bool HasAccess(HttpContext httpContext, string role)
        {
            //if there is no role system
            //every logged user has access to everything
            if(_roleProvider is null)
            {
                return true;
            }

            var session = GetSessionFromContext(httpContext);

            if (session is not { })
            {
                return false;
            }

            try
            {
                return _roleProvider.HasAccess(session, role);
            }
            catch (Exception ex)
            {
                throw new WinAuthExecutionException($"Hash access procedure failed! Check inner exception!", ex);
            }
        }

        /// <summary>
        /// Get session base on request session
        /// </summary>
        /// <param name="httpContext">HTTP context object</param>
        /// <returns>Sesson object</returns>
        /// <exception cref="WinAuthExecutionException">Thrown when IWinAuthSessionStorage fail</exception>
        private WinAuthSession? GetSessionFromContext(HttpContext httpContext)
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
                session = _sessionManager.GetSession(sid);
            }
            catch (Exception ex)
            {
                throw new WinAuthExecutionException($"Get session procedure failed! Check inner exception!", ex);
            }

            return session;
        }
        
        /// <summary>
        /// Set session cookie
        /// </summary>
        /// <param name="httpContext">HTTP context object</param>
        /// <param name="session">Session object</param>
        private void SetCookie(HttpContext httpContext, WinAuthSession session)
        {
            _contextWrapper.SetHttpCookie(httpContext, "winauth_session_id", session.SessionId.ToString(), session.ExpirationDate);
        }
    }
}
