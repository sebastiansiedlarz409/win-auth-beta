# WinAuth 0.1 Beta :lock:

Its simple library for ASP.NET CORE combining authorization/authentication via the Windows domain and a cookie-based session-like mechanism.

## Setup :black_nib:

Create login and logout handlers:
```csharp
public IActionResult Login()
{
    return View();
}

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

[WinAuthAuthorize]
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
app.UseWinAuth(typeof(Program).Assembly /*MVC ASSEMBLY*/, "/Home/Login" /*LOGIN ROUTE PATH*/, "/Home/Forbidden" /*ROLE BASED ACCESS DENIED REDIRECT PATH*/);

```

# Using :tada:

Mark your controllers actions like this using attribute:
```csharp
//non public page
[WinAuthAuthorize]
public IActionResult Page()
{
    return View();
}

//non public page
[WinAuthAuthorize("ADMIN")]
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