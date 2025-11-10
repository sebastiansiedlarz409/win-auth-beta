namespace WinAuth.Session
{
    public interface IWinAuthRoleProvider
    {
        /// <summary>
        /// Allow user to provide own role
        /// </summary>
        /// <param name="session">Session object</param>
        /// <returns>Role object - it will be save as claim</returns>
        public object? GetRole(WinAuthSession session);
    }
}
