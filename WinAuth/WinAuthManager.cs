using Microsoft.AspNetCore.Http;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using WinAuth.Session;

namespace WinAuth
{
    public sealed class WinAuthManager
    {
        private readonly IWinAuthRoleProvider? _roleProvider;
        private readonly string _domainName = string.Empty;
        private int _sessionLifeTime = 30;

        /// <summary>
        /// User can implement own session storage base on db, redis, memory or etc
        /// </summary>
        private readonly IWinAuthSessionStorage _sessionManager;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="sessionManager">Session storage implementation</param>
        /// <param name="domainName">Target domain name</param>
        /// <param name="liftime">Session life time in minutes</param>
        public WinAuthManager(IWinAuthSessionStorage sessionManager, IWinAuthRoleProvider? roleProvider, string domainName, int liftime)
        {
            _sessionManager = sessionManager;
            _roleProvider = roleProvider;

            _domainName = domainName;

            _sessionLifeTime = liftime;
        }

        /// <summary>
        /// Check credantials in domain
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
        /// Create session and its cookie
        /// IMPORTANT: Redirect is neccessary
        /// </summary>
        /// <param name="httpContext">Context</param>
        /// <param name="userName">User login</param>
        /// <returns></returns>
        public Guid CreateSession(HttpContext httpContext, string userName)
        {
            //create new session and store it
            var session = new WinAuthSession(userName, _sessionLifeTime);
            _sessionManager.StoreSession(session);

            SetCookie(httpContext, session);

            //return session id
            return session.SessionId;
        }

        /// <summary>
        /// Reads session cookie from context
        /// Check if session exist in storage
        /// Remove it
        /// </summary>
        /// <param name="httpContext">Context</param>
        public void KillSession(HttpContext httpContext)
        {
            var session = GetSessionFromContext(httpContext);

            //if session exist inside session storage remove it
            if (session is { })
            {
                _sessionManager.RemoveSession(session);
            }
        }

        /// <summary>
        /// Check session storage contains session
        /// Checks session liftime
        /// </summary>
        /// <param name="httpContext">Context</param>
        /// <returns>Valid session</returns>
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
                    var role = _roleProvider.GetRole(session);
                    if(role is { })
                    {
                        claims.Add(new Claim(ClaimTypes.Role, role!.ToString()!));
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
                    _sessionManager.UpdateSession(session);
                    SetCookie(httpContext, session);
                }
            }

            return validLifeTime;
        }

        /// <summary>
        /// Return user name
        /// Null means user is not logged in
        /// </summary>
        /// <param name="httpContext">HTTP Context</param>
        /// <returns>User name</returns>
        public string? UserName(HttpContext httpContext)
        {
            if (!httpContext.User.Identity!.IsAuthenticated)
            {
                return null;
            }

            return httpContext.User.Identity.Name;
        }

        /// <summary>
        /// Return role name
        /// </summary>
        /// <param name="httpContext">HTTP Context</param>
        /// <returns>Role name</returns>
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

            return _roleProvider.GetRole(session);
        }

        /// <summary>
        /// Check if provided role is high enough
        /// base on IWinAuthRoleProvider implementation
        /// </summary>
        /// <param name="httpContext">HTTP Context</param>
        /// <param name="role">Minimal role</param>
        /// <returns>True if access is permitted</returns>
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

            return _roleProvider.HasAccess(session, role);
        }

        /// <summary>
        /// Get session base on request session
        /// </summary>
        /// <param name="httpContext">HTTP Context</param>
        /// <returns>Sesson object</returns>
        private WinAuthSession? GetSessionFromContext(HttpContext httpContext)
        {
            //session id
            var sessionId = httpContext.Request.Cookies
                                .FirstOrDefault(t => t.Key == "winauth_session_id").Value;

            //check session id
            if (sessionId is not { })
            {
                return null;
            }

            var sid = new Guid(sessionId);
            var session = _sessionManager.GetSession(sid);

            return session;
        }

        /// <summary>
        /// Set response cookie
        /// </summary>
        /// <param name="httpContext">HTTP Context</param>
        /// <param name="session">Session object</param>
        private void SetCookie(HttpContext httpContext, WinAuthSession session)
        {
            //set cookie in context
            var options = new CookieOptions
            {
                Expires = session.ExpirationDate,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            };
            httpContext.Response.Cookies.Append("winauth_session_id", session.SessionId.ToString(), options);
        }
    }
}
