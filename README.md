# WINAUTH 0.1.0-beta

Its simple library for ASP.NET CORE combining authorization/authentication via the Windows domain and a cookie-based session-like mechanism. At the moment its beta version.

## Setup

Create exacly one forbidden action using attribute (all attempts at unauthorized access to actions requiring a higher role will be redirected here):
```csharp
[WinAuthAccess(WinAuthAccess.Forbidden)]
public IActionResult Forbidden()
{
    return View();
}
```

Create exacly one login action using attribute (all attempts at unauthorized access to actions requiring login will be redirected here):
```csharp
[WinAuthAccess(WinAuthAccess.Login)]
public IActionResult Login()
{
    return View();
}
```

Create login and logut handlers actions:
```csharp
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

Create own session storage mechanism by implementing IWinAuthSessionStorage and register it in DI.
```csharp
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

OPTIONAL: Create own role provider mechanism by implementing IWinAuthRoleProvider adn register it in DI. By default there is no role provider - all actions with specified role will be freely available.
```csharp
public interface IWinAuthRoleProvider
{
    public object? GetRole(WinAuthSession session);
    public bool HasAccess(WinAuthSession session, object? role);
}

//program.cs
//register it before calling AddWinAuth()
builder.Services.AddSingleton<IWinAuthRoleProvider, WinAuthRoleProvider>();
```

Configure DI and Middleware
```csharp
//program.cs
//register what is neccessary
builder.Services.AddWinAuth("domain.local" /*DOMAIN NAME*/, 30 /*SESSION LIFETIME IN MINUTES*/);
...
//base asp routing setup
app.UseRouting();
...
//use middleware after routing
app.UseWinAuth(typeof(Program).Assembly /*MVC ASSEMBLY*/, "login" /*LOGIN ROUTE NAME (WILL BE CREATED BY LIB)*/, "forbidden" /*FORBIDDEN ROUTE NAME (ACCESS DENIED REDIRECT)*/);

```

# Using

Mark your controllers actions like this using attribute:
```csharp
//non public page
[WinAuthAccess(WinAuthAccess.Authorized)]
public IActionResult Page()
{
    return View();
}

//non public page
[WinAuthAccess(WinAuthAccess.Authorized, "ADMIN")]
public IActionResult Page2()
{
    return View();
}

//public page
public IActionResult Index()
{
    return View();
}
```

Checking if authenticated in razor

```csharp
@inject WinAuth.WinAuthManager authManager

//...

@if (authManager.UserRole(ViewContext.HttpContext) is { })
{
    //razor
}
@if (authManager.IsAuthenticated(ViewContext.HttpContext))
{
    //razor
}
else
{
    //razor
}
```