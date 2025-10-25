using Microsoft.AspNetCore.Http;

namespace WinAuth
{
    public class WinAuthManager
    {
        private List<WinAuthSession> _sessions = new List<WinAuthSession>();

        public Guid CreateSession(HttpContext httpContext)
        {
            var session = new WinAuthSession();
            _sessions.Add(session);

            httpContext.Response.Cookies.Append("winauth_session_id", session.SessionId.ToString());

            return session.SessionId;
        }

        public void KillSession(HttpContext httpContext)
        {
            var sessionId = httpContext.Request.Cookies
                                .FirstOrDefault(t => t.Key == "winauth_session_id").Value;

            if (sessionId is not { })
            {
                return;
            }

            var sid = new Guid(sessionId);

            var session = _sessions.FirstOrDefault(t => t.SessionId == sid);

            if (session is { })
            {
                _sessions.Remove(session);
            }
        }

        public bool IsSessionAlive(string sessionId)
        {
            if(sessionId is not { })
            {
                return false;
            }

            var sid = new Guid(sessionId);

            var session = _sessions.FirstOrDefault(t=>t.SessionId == sid);

            if(session is { })
            {
                return session.ExpirationDate >= DateTime.Now;
            }

            return false;
        }
    }
}
