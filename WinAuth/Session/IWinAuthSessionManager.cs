namespace WinAuth.Session
{
    public interface IWinAuthSessionManager
    {
        public void StoreSession(WinAuthSession session);
        
        public WinAuthSession? GetSession(Guid sessionId);

        public void RemoveSession(WinAuthSession session);
    }
}
