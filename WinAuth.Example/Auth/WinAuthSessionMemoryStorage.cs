
using WinAuth.Session;

namespace WinAuth.Example.Auth
{
    public sealed class WinAuthSessionMemoryStorage : IWinAuthSessionStorage
    {
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1);
        private List<WinAuthSession> _sessions = new List<WinAuthSession>();

        /// <summary>
        /// For this specific IWinAuthSessionStorage implementation as data is store in memory
        /// its necessary to clean it
        /// </summary>
        /// <param name="sessionId"></param>
        /// <exception cref="NotImplementedException"></exception>
        private async Task CleanupSession()
        {
            await _semaphore.WaitAsync();
            _sessions.RemoveAll(t => t.ExpirationDate < DateTime.UtcNow);
            _semaphore.Release();
        }

        public async Task<WinAuthSession?> GetSessionAsync(Guid sessionId)
        {
            //remove expired sessions
            await CleanupSession();

            await _semaphore.WaitAsync();

            WinAuthSession? session = _sessions.FirstOrDefault(t => t.SessionId == sessionId);
            _semaphore.Release();

            return session;
        }

        public async Task UpdateSessionAsync(WinAuthSession session)
        {
            await _semaphore.WaitAsync();

            var updateSession = _sessions.FirstOrDefault(t => t.SessionId == session.SessionId);
            if (updateSession is { })
            {
                updateSession.ExpirationDate = session.ExpirationDate;
            }
            _semaphore.Release();
        }

        public async Task RemoveSessionAsync(WinAuthSession session)
        {
            await _semaphore.WaitAsync();

            _sessions.Remove(session);
            _semaphore.Release();
        }

        public async Task StoreSessionAsync(WinAuthSession session)
        {
            await _semaphore.WaitAsync();

            _sessions.Add(session);
            _semaphore.Release();
        }
    }
}
