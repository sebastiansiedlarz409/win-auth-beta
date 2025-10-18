namespace WinAuth
{
    internal class WinAuthSession
    {
        public Guid SessionId { get; set; }

        public DateTime ExpirationDate { get; set; }

        public WinAuthSession()
        {
            SessionId = Guid.NewGuid();
            ExpirationDate = DateTime.Now.AddMinutes(3);
        }
    }
}
