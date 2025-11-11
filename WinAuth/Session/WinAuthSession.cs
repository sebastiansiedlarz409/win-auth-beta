namespace WinAuth.Session
{
    public class WinAuthSession
    {
        public Guid SessionId { get; set; }

        public DateTime ExpirationDate { get; set; }

        public string UserName { get; set; }

        public WinAuthSession(string userName, int sessionLifeTime)
        {
            SessionId = Guid.NewGuid();
            ExpirationDate = DateTime.UtcNow.AddMinutes(sessionLifeTime);

            UserName = userName;
        }
    }
}
