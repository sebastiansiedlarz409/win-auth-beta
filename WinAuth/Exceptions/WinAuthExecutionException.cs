namespace WinAuth.Exceptions
{
    public class WinAuthExecutionException : Exception
    {
        public WinAuthExecutionException(string msg) : base(msg) { }
        public WinAuthExecutionException(string msg, Exception innerException) : base(msg, innerException) { }
    }
}
