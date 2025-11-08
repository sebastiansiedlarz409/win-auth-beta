
namespace WinAuth.Session
{
    public class WinAuthSessionMemoryStorage : IWinAuthSessionStorage
    {
        private List<WinAuthSession> _sessions = new List<WinAuthSession>();

        public WinAuthSession? GetSession(Guid sessionId)
        {
            return _sessions.FirstOrDefault(t => t.SessionId == sessionId);
        }

        public void RemoveSession(WinAuthSession session)
        {
            _sessions.Remove(session);
        }

        public void StoreSession(WinAuthSession session)
        {
            _sessions.Add(session);
        }
    }
}
