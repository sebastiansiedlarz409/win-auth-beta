using WinAuth.Attributes;

namespace WinAuth.Tests.TestControllers
{
    public class Test2Controller
    {
        [WinAuthAuthorize(false)]
        public void TestAction1()
        {

        }
    }
}
