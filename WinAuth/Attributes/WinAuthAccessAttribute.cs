namespace WinAuth.Attributes
{
    public enum WinAuthAccess
    {
        Authorized = 0,
        Login = 1,
        Forbidden = 2,
    }

    public class WinAuthAccessAttribute : Attribute
    {
        public WinAuthAccess Access { get; private set; }

        public string? Role {  get; private set; }

        public WinAuthAccessAttribute(WinAuthAccess access, string? role = null)
        {
            Access = access;
            Role = role;
        }
    }
}
