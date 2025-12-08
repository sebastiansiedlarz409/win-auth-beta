namespace WinAuth.Session
{
    public interface IWinAuthRoleProvider
    {
        /// <summary>
        /// Allow user to provide own role
        /// </summary>
        /// <param name="session">Session object</param>
        /// <returns>Role name - it will be save as claim</returns>
        Task<string?> GetRoleAsync(WinAuthSession session);

        /// <summary>
        /// Check if user's role is enought to get access
        /// </summary>
        /// <param name="session">Session object</param>
        /// <param name="role">Role name</param>
        /// <returns>True if user has access</returns>
        Task<bool> HasAccessAsync(WinAuthSession session, string role);
    }
}
