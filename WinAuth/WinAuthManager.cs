using Microsoft.AspNetCore.Http;

namespace WinAuth
{
    public class WinAuthManager
    {
        private List<WinAuthSession> _sessions = new List<WinAuthSession>();

        /// <summary>
        /// Create session and its cookie
        /// </summary>
        /// <param name="httpContext">Context</param>
        /// <returns></returns>
        public Guid CreateSession(HttpContext httpContext)
        {
            //create new session and store it
            var session = new WinAuthSession();
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
                return session.ExpirationDate >= DateTime.Now;
            }

            return false;
        }
    }
}
