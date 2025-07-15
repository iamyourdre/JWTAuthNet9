This is a structured guide to building an authentication system using **ASP.NET Core Web API**, **Entity Framework Core**, and **JWT (JSON Web Tokens)**.

---

## 🧱 Folder Structure (Best Practice)

```
/JWTAuthNet9
│
├── Controllers/              → API endpoints
│   └── AuthController.cs
│
├── Data/                     → Database context
│   └── UserDbContext.cs
│
├── Entities/                 → EF Core database models
│   └── User.cs
│
├── Models/                     → Data Transfer Objects for requests
│   └── UserDto.cs
│
├── Services/                 → Business logic (Service Layer)
│   └── IAuthService.cs
│   └── AuthService.cs
│
├── appsettings.json          → Configurations (JWT, connection string)
├── Program.cs                → Entry point and DI setup

```

---

# ▶️ A. Basic Setup

### 1. Create Entity

📄 `Entities/User.cs`

```csharp
public class User
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
}

```

### 2. Create DTO

📄 `Models/UserDto.cs`

```csharp
public class UserDto
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

```

> ✅Why DTO? To avoid exposing your full database entity. Keep data clean and secure.
> 

---

# ▶️ B. JWT Authentication Logic

### 1. Install Required Packages

```bash
dotnet add package Microsoft.AspNetCore.Identity
dotnet add package Microsoft.IdentityModel.Tokens
dotnet add package System.IdentityModel.Tokens.Jwt

```

### 2. Add JWT settings to `appsettings.json`

```json
{
  "AppSettings": {
    "Token": "your-super-secure-key-here",
    "Issuer": "MyApp",
    "Audience": "MyAppUsers"
  },
  "ConnectionStrings": {
    "UserDatabase": "Data Source=(localdb)\\MSSQLLocalDB;Initial Catalog=YourDB;Integrated Security=True;"
  }
}

```

---

# ▶️ C. Add EF Core & Configure DB

### 1. Create Context

📄 `Data/UserDbContext.cs`

```csharp
public class UserDbContext : DbContext
{
    public UserDbContext(DbContextOptions<UserDbContext> options)
        : base(options) { }

    public DbSet<User> Users { get; set; }
}

```

### 2. Register DB in `Program.cs`

```csharp
builder.Services.AddDbContext<UserDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("UserDatabase")));

```

### 3. Run Migration

```bash
Add-Migration Initial
Update-Database

```

---

# ▶️ D. Service Layer Refactor

### Why Should You Use Service Layer?

| Reason | Explanation |
| --- | --- |
| **Separation of Concerns** | Move business logic out of the controller |
| **Clean Code** | Controller becomes smaller and easier to test |
| **Reusability** | Logic can be reused across other parts of the app |
| **Testing** | Easier to unit test services without dealing with HTTP |

### 1. Interface

📄 `Services/IAuthService.cs`

```csharp
public interface IAuthService
{
    Task<User?> RegisterAsync(UserDto request);
    Task<string?> LoginAsync(UserDto request);
}

```

### 2. Implementation

📄 `Services/AuthService.cs`

```csharp
public class AuthService : IAuthService
{
    private readonly UserDbContext context;
    private readonly IConfiguration configuration;

    public AuthService(UserDbContext context, IConfiguration configuration)
    {
        this.context = context;
        this.configuration = configuration;
    }

    public async Task<User?> RegisterAsync(UserDto request)
    {
        if (await context.Users.AnyAsync(u => u.Username == request.Username))
            return null;

        var user = new User
        {
            Username = request.Username,
            PasswordHash = new PasswordHasher<User>().HashPassword(new User(), request.Password)
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();
        return user;
    }

    public async Task<string?> LoginAsync(UserDto request)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null) return null;

        var result = new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password);
        if (result == PasswordVerificationResult.Failed) return null;

        return CreateToken(user);
    }

    private string CreateToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["AppSettings:Token"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            issuer: configuration["AppSettings:Issuer"],
            audience: configuration["AppSettings:Audience"],
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

```

**Modified Lines Explained:**

- **Added null returns** → to handle validation failure cases.
- **PasswordHasher** reused from controller.
- **CreateToken()** moved for reusability and separation.

### 3. Refactor the Controller

📄 `Controllers/AuthController.cs`

```csharp
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService authService;

    public AuthController(IAuthService authService)
    {
        this.authService = authService;
    }

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDto request)
    {
        var user = await authService.RegisterAsync(request);
        if (user == null)
            return BadRequest("User already exists");

        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<string>> Login(UserDto request)
    {
        var token = await authService.LoginAsync(request);
        if (token == null)
            return BadRequest("Invalid username or password");

        return Ok(token);
    }
}

```

### 4. Register the Service

📄 `Program.cs`

```csharp
builder.Services.AddScoped<IAuthService, AuthService>();

```

---

## TL;DR Summary

| Layer | Purpose |
| --- | --- |
| **Entities** | EF Core models (DB) |
| **DTOs** | Safe data shape for requests/responses |
| **Controllers** | Route handling |
| **Services** | Auth logic (register, login, token) |
| **DbContext** | EF connection to SQL Server |
| **Program.cs** | DI setup and config |
| **appsettings.json** | JWT and DB settings |

---

# ▶️ E. Securing Endpoints (JWT)

### 1. Add Protected Endpoint

📄 `AuthController.cs`

```csharp
[Authorize]
[HttpGet("authenticated")]
public IActionResult AuthenticatedOnlyEndpoint()
{
    if (User.Identity?.IsAuthenticated == true)
        return Ok("You are authenticated");

    return Unauthorized("❌ You are not authenticated");
}

```

> 🔒 [Authorize] attribute makes the route accessible only if a valid JWT token is attached to the request (Authorization: Bearer <token>).
> 

---

### 2. Enable JWT Auth in `Program.cs`

📄 `Program.cs`

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            ValidIssuer = builder.Configuration["AppSettings:Issuer"],
            ValidAudience = builder.Configuration["AppSettings:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["AppSettings:Token"]!)
            )
        };
    });
    
...

builder.Services.AddAuthorization(); // <-- Don't forget this

```

> 🧠 Explanation: This tells .NET to verify the signature, issuer, and audience from your token using your secret key.
> 

---

# ▶️ F. Role-Based Access Control

### 1. Update Entity

📄 `Entities/User.cs`

```csharp
public class User
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;

    public string Role { get; set; } = "User"; // Default to "User"
}
```

> ⚠️ Add "Role": "Admin" manually on a test user during registration or through DB.
> 

---

### 2. Add Admin-Only Endpoint

📄 `AuthController.cs`

```csharp
...

[Authorize(Roles = "Admin")]
[HttpGet("admin-only")]
public IActionResult AdminOnlyEndpoint()
{
    if (User.Identity?.IsAuthenticated == true)
        return Ok("You are admin");

    return Unauthorized("❌ You are not admin");
}

...
```

> This endpoint only works if the logged-in user has a claim like Role: "Admin".
> 

---

### 3. Add Role to JWT Claims

📄 `AuthService.cs`

```csharp
private string CreateToken(User user)
{
    var claims = new List<Claim>
    {
		    ...
        new Claim(ClaimTypes.Role, user.Role) // <-- Add role claim
    };
    ...
}

```

---

## 🔁 Recap: Authorization Flow

1. Client logs in → receives a **JWT token**
2. Client stores and sends token in `Authorization: Bearer <token>` header
3. API validates the token using config in `Program.cs`
4. If valid:
    - `[Authorize]` gives access to protected routes
    - `[Authorize(Roles = "Admin")]` checks for role inside JWT claims

---

## Bonus Testing Tip

Use **Postman** or **Thunder Client** with headers:

```
Authorization: Bearer <your_jwt_token>

```

Then test:

- `/api/auth/authenticated` for any logged-in user
- `/api/auth/admin-only` only if JWT has Role: Admin

---

## TL;DR: Why All This?

| Feature | Purpose |
| --- | --- |
| `Authorize` | Protect routes from anonymous access |
| JWT Config | Validates token signature, expiry, issuer, audience |
| Role Claim | Enables role-based security |
| Service Layer | Keeps Auth logic separated, clean, and testable |
| DTOs | Prevent exposing full DB entity |

---

# ▶️ G. Implementing Refresh Token

---

## Why Use Refresh Tokens?

JWT **access tokens** are usually **short-lived** (e.g., 15 mins–1 hour) for security. But we don’t want users to log in every time the access token expires. That's where **refresh tokens** come in:

| Token Type | Purpose | Expiry | Stored |
| --- | --- | --- | --- |
| Access Token | Authenticates the user (used in headers) | Short-lived (e.g. 1h) | Client |
| Refresh Token | Gets a new access token when old one expires | Long-lived (e.g. 7d) | DB & Client |

---

## Step-by-Step Implementation

---

### 1. Update Entity with Refresh Token Fields

📄 `Entities/User.cs`

```csharp
public class User
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "User";

    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
}

```

```bash
Add-Migration AddRefreshToken
Update-Database

```

---

### 2. Create TokenResponseDto

📄 `Models/TokenResponseDto.cs`

```csharp
public class TokenResponseDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
}

```

---

### 3. Add Refresh Token Generation in Service

📄 `Services/AuthService.cs`

```csharp
private string GenerateRefreshToken()
{
    var randomNumber = new byte[32];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(randomNumber);
    return Convert.ToBase64String(randomNumber);
}

private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
{
    var refreshToken = GenerateRefreshToken();
    user.RefreshToken = refreshToken;
    user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
    await context.SaveChangesAsync();
    return refreshToken;
}

```

---

### 4. Modify LoginAsync to Return TokenResponse

📄 `IAuthService.cs`

```csharp
Task<TokenResponseDto?> LoginAsync(UserDto request);

```

📄 `AuthService.cs`

```csharp
public async Task<TokenResponseDto?> LoginAsync(UserDto request)
{
    var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
    if (user == null || new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
    {
        return null;
    }

    return await CreateTokenResponse(user);
}

// Extracted reusable method
private async Task<TokenResponseDto> CreateTokenResponse(User user)
{
    return new TokenResponseDto
    {
        AccessToken = CreateToken(user),
        RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
    };
}

```

> 🧠 Why extract CreateTokenResponse()? To avoid repeating the same code for both login and refresh.
> 

---

### 5. Update AuthController to Return Both Tokens

📄 `AuthController.cs`

```csharp
[HttpPost("login")]
public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
{
    var result = await authService.LoginAsync(request);
    if (result == null) return BadRequest("Invalid credentials");

    return Ok(result);
}

```

---

### 6. Add Refresh Token Endpoint

📄 `Models/RefreshTokenRequestDto.cs`

```csharp
public class RefreshTokenRequestDto
{
    public Guid UserId { get; set; }
    public required string RefreshToken { get; set; }
}

```

📄 `IAuthService.cs`

```csharp
Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request);

```

📄 `AuthService.cs`

```csharp
public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request)
{
    var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
    if (user == null) return null;

    return await CreateTokenResponse(user);
}

private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
{
    var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId && u.RefreshToken == refreshToken);
    if (user == null || user.RefreshTokenExpiryTime < DateTime.UtcNow)
    {
        return null;
    }
    return user;
}

```

📄 `AuthController.cs`

```csharp
[HttpPost("refresh-token")]
public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
{
    var result = await authService.RefreshTokenAsync(request);
    if (result == null) return Unauthorized("Refresh token is invalid or expired");

    return Ok(result);
}

```

---

## 🧪 Testing Flow

1. **Login**
    - POST `/api/auth/login`
    - Response → `accessToken` + `refreshToken`
2. **Use `accessToken`** to call protected routes with:
    - `Authorization: Bearer <accessToken>`
3. **When expired**, POST to `/api/auth/refresh-token` with:
    
    ```json
    {
      "userId": "<user-guid>",
      "refreshToken": "<refreshToken>"
    }
    
    ```
    
    - Get back a new access + refresh token.

---

## Summary Cheatsheet

| 🔧 Task | 🔑 Code |
| --- | --- |
| Generate secure string | `GenerateRefreshToken()` |
| Store & expire token | `RefreshToken`, `RefreshTokenExpiryTime` |
| Validate on refresh | `ValidateRefreshTokenAsync()` |
| Return both tokens | `CreateTokenResponse()` |
| Controller endpoint | `/login`, `/refresh-token` |

---

# 🔑 Access Token — *Where is it “implemented”?*

In this project, **access token is implemented via the `CreateToken(User user)` method** in your `AuthService`. Here's the key line:

```csharp
return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
```

This line takes all the **claims**, signs them using your secret key, and creates the **access token (JWT)**.

---

## Here's what happens under the hood:

When you log in:

```csharp
[HttpPost("login")]
public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
{
    var result = await authService.LoginAsync(request);
    return Ok(result); // ⬅️ Includes the access token
}

```

That access token is generated by:

```csharp
private string CreateToken(User user)
{
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Role, user.Role)
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["AppSettings:Token"]!));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

    var tokenDescriptor = new JwtSecurityToken(
        issuer: configuration["AppSettings:Issuer"],
        audience: configuration["AppSettings:Audience"],
        claims: claims,
        expires: DateTime.Now.AddHours(1),
        signingCredentials: creds
    );

    return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor); // ⬅️ Access token generated here
}

```

So yes, the **access token is there** — it's just:

- **returned immediately in the login or refresh-token response**
- **not stored in the database** (because it’s stateless)
- **used by the client to access secured endpoints**

---

## Access Token in Use

Anywhere you do this:

```csharp
[Authorize]
public IActionResult SomeProtectedEndpoint()
{
    var username = User.Identity?.Name;
    ...
}

```

It’s the **access token** that's being validated by ASP.NET Core's built-in middleware.

You registered that here in `Program.cs`:

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["AppSettings:Issuer"],
            ValidAudience = builder.Configuration["AppSettings:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["AppSettings:Token"]))
        };
    });

```

This middleware:

- Intercepts every `[Authorize]` request
- Checks the `Authorization: Bearer <access_token>` header
- Verifies signature, expiry, issuer, etc.
- Injects `User` claims for your controller

---

## Summary

| Concept | Where Implemented |
| --- | --- |
| **Access Token** | `CreateToken()` method in `AuthService` |
| **Refresh Token** | `GenerateRefreshToken()` and stored in DB |
| **Login Returns** | Both `AccessToken` and `RefreshToken` in `TokenResponseDto` |
| **Token Validation** | Via JWT middleware in `Program.cs` |
| **Secure Endpoint** | Using `[Authorize]` attribute |

---

Let me know if you want:

- Example of sending token from a front-end
- Best practice for securing refresh tokens (e.g., HttpOnly cookies)
- Logout endpoint (revoke refresh token)

You're on the right track 🔥