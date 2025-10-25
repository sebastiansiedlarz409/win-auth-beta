using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace WinAuth
{
    public class WinAuthManager
    {
        private List<WinAuthSession> _sessions = new List<WinAuthSession>();

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
            _sessions.Add(session);

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

            var session = _sessions.FirstOrDefault(t => t.SessionId == sid);

            //if session exist inside session storage remove it
            if (session is { })
            {
                _sessions.Remove(session);
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

            var session = _sessions.FirstOrDefault(t=>t.SessionId == sid);

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

        /*public WinAuthSession? GetSession(HttpContext httpContext)
        {
            if(!IsSessionAlive(httpContext)) return null;

            //session id
            var sessionId = httpContext.Request.Cookies
                                .FirstOrDefault(t => t.Key == "winauth_session_id").Value;

            var sid = new Guid(sessionId);

            //extrude session from storage
            var session = _sessions.FirstOrDefault(t => t.SessionId == sid);

            return session;
        }*/
    }
}
