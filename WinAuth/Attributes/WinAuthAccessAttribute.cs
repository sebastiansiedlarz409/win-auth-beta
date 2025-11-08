namespace WinAuth.Attributes
{
    public enum WinAuthAccess
    {
        Authorized = 0,
        Login = 1,
    }

    public class WinAuthAccessAttribute : Attribute
    {
        public WinAuthAccess Access { get; private set; }

        public WinAuthAccessAttribute(WinAuthAccess access)
        {
            Access = access;
        }
    }
}
