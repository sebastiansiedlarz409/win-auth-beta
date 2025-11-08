
namespace WinAuth.Session
{
    public class WinAuthSessionMemoryStorage : IWinAuthSessionStorage
    {
        private readonly object _lock = new object();
        private List<WinAuthSession> _sessions = new List<WinAuthSession>();

        public WinAuthSession? GetSession(Guid sessionId)
        {
            WinAuthSession? session = null;
            lock (_lock)
            {
                session = _sessions.FirstOrDefault(t => t.SessionId == sessionId);
            }
            return session;
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
