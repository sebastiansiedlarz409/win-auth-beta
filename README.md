# WINAUTH 0.1.0-beta

Its simple library for ASP.NET CORE combining authorization/authentication via the Windows domain and a cookie-based session-like mechanism. At the moment its beta version.

## Setup

Create exacly one login action using attribute:
```
[WinAuthAccess(WinAuthAccess.Login)]
public IActionResult Login()
{
    return View();
}
```

Create login and logut handlers actions:
```
[HttpPost]
public IActionResult LoginUser(string user, string pass)
{
    if (_authManager.Login(user, pass))
    {
        _authManager.CreateSession(HttpContext, user);
        return RedirectToAction("Page"); //login succeed - go to protected page
    }

    return RedirectToAction("Login"); //login failed - go to login page
}

//clear session
[WinAuthAccess(WinAuthAccess.Authorized)]
public IActionResult Logout()
{
    _authManager.KillSession(HttpContext);

    return RedirectToAction("Index");
}
```

OPTIONAL: Create own session storage mechanism by implementing IWinAuthSessionStorage and register it as singleton. Default one will store session in memory.
```
public interface IWinAuthSessionStorage
{
    public void StoreSession(WinAuthSession session);
    public WinAuthSession? GetSession(Guid sessionId);
    public void RemoveSession(WinAuthSession session);
}

//program.cs
//register it before calling AddWinAuth()
builder.Services.AddSingleton<IWinAuthSessionStorage, WinAuthSessionMemoryStorage>();
```

Configure DI and Middleware
```
//program.cs
//register what is neccessary
builder.Services.AddWinAuth("domain.local" /*DOMAIN NAME*/, 30 /*SESSION LIFETIME IN MINUTES*/);
...
//base asp routing setup
app.UseRouting();
...
//use middleware after routing
app.UseWinAuth(typeof(Program).Assembly /*MVC ASSEMBLY*/, "login" /*LOGIN ROUTE NAME (WILL BE CREATED BY LIB)*/);

```

# Using

Mark your controllers actions like this using attribute:
```
//non public page
[WinAuthAccess(WinAuthAccess.Authorized)]
public IActionResult Page()
{
    return View();
}

//public page
public IActionResult Index()
{
    return View();
}
```