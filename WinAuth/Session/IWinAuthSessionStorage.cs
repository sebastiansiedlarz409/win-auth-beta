namespace WinAuth.Session
{
    public interface IWinAuthSessionStorage
    {
        /// <summary>
        /// Insert session to storage
        /// </summary>
        /// <param name="session">Session object</param>
        Task StoreSessionAsync(WinAuthSession session);

        /// <summary>
        /// Additional method for session updating
        /// WinAuth needs to update session life time when its near to end
        /// This metods allow user to handle save individually for better performance
        /// </summary>
        /// <param name="session"></param>
        Task UpdateSessionAsync(WinAuthSession session);
        
        /// <summary>
        /// Retrive session from storage
        /// </summary>
        /// <param name="sessionId">Session Id</param>
        /// <returns>Session object</returns>
        Task<WinAuthSession?> GetSessionAsync(Guid sessionId);

        /// <summary>
        /// Remove session from storage
        /// </summary>
        /// <param name="session">Session object</param>
        Task RemoveSessionAsync(WinAuthSession session);
    }
}
