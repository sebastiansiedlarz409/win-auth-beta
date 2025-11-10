using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.DirectoryServices.AccountManagement;
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
        public WinAuthManager(IWinAuthSessionStorage sessionManager, IWinAuthRoleProvider roleProvider, string domainName, int liftime)
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

            //set cookie in context
            httpContext.Response.Cookies.Append("winauth_session_id", session.SessionId.ToString());

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
            //get session cookie from context
            var sessionId = httpContext.Request.Cookies
                                .FirstOrDefault(t => t.Key == "winauth_session_id").Value;

            //return if cookie does not exist
            if (sessionId is not { })
            {
                return;
            }

            var sid = new Guid(sessionId);

            var session = _sessionManager.GetSession(sid);

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
            //session id
            var sessionId = httpContext.Request.Cookies
                                .FirstOrDefault(t => t.Key == "winauth_session_id").Value;

            //check session id
            if (sessionId is not { })
            {
                return false;
            }

            var sid = new Guid(sessionId);
            var session = _sessionManager.GetSession(sid);

            //if session exist in storage check liftime
            if (session is not { })
            {
                return false;
            }

            bool validLifeTime = session.ExpirationDate >= DateTime.Now;

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
                }
            }

            return validLifeTime;
        }
    }
}
