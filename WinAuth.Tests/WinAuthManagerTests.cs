using Microsoft.AspNetCore.Http;
using Moq;
using WinAuth.Session;

namespace WinAuth.Tests
{
    public class WinAuthManagerTests
    {
        private Guid sessionId = Guid.NewGuid();

        private IWinAuthSessionStorage MockSessionStorage()
        {
            var mock = new Mock<IWinAuthSessionStorage>();

            mock.Setup(t => t.GetSession(new Guid())).Returns(new WinAuthSession("test.testowski", 5));

            return mock.Object;
        }

        private HttpContext MockHttpContext()
        {
            var cookie = new KeyValuePair<string, string>("winauth_session_id", sessionId.ToString());
            var storage = new List<KeyValuePair<string, string>>() { cookie };

            var mockCookieCollection = new Mock<IRequestCookieCollection>();
            mockCookieCollection.Setup(t => t.GetEnumerator()).Returns(storage.GetEnumerator());

            var mockHttpRequest = new Mock<HttpRequest>();
            mockHttpRequest.Setup(t => t.Cookies).Returns(mockCookieCollection.Object);

            var mockHttpContext = new Mock<HttpContext>();
            mockHttpContext.Setup(t => t.Request).Returns(mockHttpRequest.Object);

            return mockHttpContext.Object;
        }

        [Fact]
        public void Test1()
        {
            var httpContext = MockHttpContext();
            var storage = MockSessionStorage();
            WinAuthManager authManager = new WinAuthManager(storage, null, "", 5);

            Assert.Equal("test.testowski", authManager.UserName(httpContext));
        }
    }
}
