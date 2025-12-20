using WinAuth.Attributes;

namespace WinAuth.Tests.TestControllers
{
    public class TestController
    {
        [WinAuthAuthorize]
        public void TestAction()
        {

        }

        [WinAuthAuthorize(false)]
        public void TestAction2()
        {

        }

        [WinAuthAuthorize(true, "ADMIN")]
        public void TestAction3()
        {

        }

        public void TestAction4()
        {

        }
    }
}
