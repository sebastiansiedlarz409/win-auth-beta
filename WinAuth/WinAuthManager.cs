using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using WinAuth.Session;

namespace WinAuth
{
    public class WinAuthManager
    {
        /// <summary>
        /// User can implement own session storage base on db, redis, memory or etc
        /// </summary>
        private readonly IWinAuthSessionManager _sessionManager;

        public WinAuthManager(IWinAuthSessionManager sessionManager)
        {
            _sessionManager = sessionManager;
        }

        /// <summary>
        /// Create session and its cookie
        /// </summary>
        /// <param name="httpContext">Context</param>
        /// <param name="userName">User login</param>
        /// <returns></returns>
        public Guid CreateSession(HttpContext httpContext, string userName)
        {
            //create new session and store it
            var session = new WinAuthSession(userName);
            _sessionManager.StoreSession(session);

            //set cookie in context
            httpContext.Response.Cookies.Append("winauth_session_id", session.SessionId.ToString());

            //setup identity
            IsSessionAlive(httpContext);

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
        /// <returns></returns>
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
            if(session is { })
            {
                bool valid = session.ExpirationDate >= DateTime.Now;

                if (valid)
                {
                    //setup user data for app purposes
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, session.UserName),
                    };

                    var identity = new ClaimsIdentity(claims, "WinAuth");
                    var principal = new ClaimsPrincipal(identity);

                    httpContext.User = principal;
                }

                return valid;
            }

            return false;
        }
    }
}
