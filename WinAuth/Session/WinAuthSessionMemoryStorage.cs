
using System;

namespace WinAuth.Session
{
    public class WinAuthSessionMemoryStorage : IWinAuthSessionStorage
    {
        private readonly object _lock = new object();
        private List<WinAuthSession> _sessions = new List<WinAuthSession>();

        /// <summary>
        /// For this specific IWinAuthSessionStorage implementation as data is store in memory
        /// its necessary to clean it
        /// </summary>
        /// <param name="sessionId"></param>
        /// <exception cref="NotImplementedException"></exception>
        private void CleanupSession()
        {
            lock (_lock)
            {
                _sessions.RemoveAll(t=>t.ExpirationDate<DateTime.UtcNow);
            }
        }

        public WinAuthSession? GetSession(Guid sessionId)
        {
            //remove expired sessions
            CleanupSession();

            WinAuthSession? session = null;
            lock (_lock)
            {
                session = _sessions.FirstOrDefault(t => t.SessionId == sessionId);
            }
            return session;
        }

        public void UpdateSession(WinAuthSession session)
        {
            lock (_lock)
            {
                var updateSession = _sessions.FirstOrDefault(t => t.SessionId == session.SessionId);
                if(updateSession is { })
                {
                    updateSession.ExpirationDate = session.ExpirationDate;
                    updateSession.UserName = session.UserName;
                }
            }
        }

        public void RemoveSession(WinAuthSession session)
        {
            lock (_lock)
            {
                _sessions.Remove(session);
            }
        }

        public void StoreSession(WinAuthSession session)
        {
            lock(_lock)
            {
                _sessions.Add(session);
            }
        }
    }
}
