namespace WinAuth.Session
{
    public interface IWinAuthSessionManager
    {
        /// <summary>
        /// Insert session to storage
        /// </summary>
        /// <param name="session">Session object</param>
        public void StoreSession(WinAuthSession session);
        
        /// <summary>
        /// Retrive session from storage
        /// </summary>
        /// <param name="sessionId">Session Id</param>
        /// <returns>Session object</returns>
        public WinAuthSession? GetSession(Guid sessionId);

        /// <summary>
        /// Remove session from storage
        /// </summary>
        /// <param name="session">Session object</param>
        public void RemoveSession(WinAuthSession session);
    }
}
