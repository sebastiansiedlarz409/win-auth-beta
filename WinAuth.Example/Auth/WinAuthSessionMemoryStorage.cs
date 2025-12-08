
using WinAuth.Session;

namespace WinAuth.Example.Auth
{
    public sealed class WinAuthSessionMemoryStorage : IWinAuthSessionStorage
    {
        private readonly object _lock = new object();
        private List<WinAuthSession> _sessions = new List<WinAuthSession>();

        /// <summary>
        /// For this specific IWinAuthSessionStorage implementation as data is store in memory
        /// its necessary to clean it
        /// </summary>
        /// <param name="sessionId"></param>
        /// <exception cref="NotImplementedException"></exception>
        private async Task CleanupSession()
        {
            lock (_lock)
            {
                _sessions.RemoveAll(t=>t.ExpirationDate<DateTime.UtcNow);
            }
        }

        public async Task<WinAuthSession?> GetSessionAsync(Guid sessionId)
        {
            //remove expired sessions
            await CleanupSession();

            WinAuthSession? session = null;
            lock (_lock)
            {
                session = _sessions.FirstOrDefault(t => t.SessionId == sessionId);
            }
            return session;
        }

        public async Task UpdateSessionAsync(WinAuthSession session)
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

        public async Task RemoveSessionAsync(WinAuthSession session)
        {
            lock (_lock)
            {
                _sessions.Remove(session);
            }
        }

        public async Task StoreSessionAsync(WinAuthSession session)
        {
            lock(_lock)
            {
                _sessions.Add(session);
            }
        }
    }
}
