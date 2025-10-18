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
