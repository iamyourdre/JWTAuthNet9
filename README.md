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

## ✅ A. Basic Setup

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

## ✅ B. JWT Authentication Logic

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

## ✅ C. Add EF Core & Configure DB

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

## ✅ D. Service Layer Refactor

### ❓ Why Should You Use Service Layer?

| Reason | Explanation |
| --- | --- |
| **Separation of Concerns** | Move business logic out of the controller |
| **Clean Code** | Controller becomes smaller and easier to test |
| **Reusability** | Logic can be reused across other parts of the app |
| **Testing** | Easier to unit test services without dealing with HTTP |

---

## ✅ E. AuthService Implementation

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

✅ **Modified Lines Explained:**

- **Added null returns** → to handle validation failure cases.
- **PasswordHasher** reused from controller.
- **CreateToken()** moved for reusability and separation.

---

## ✅ F. Refactor the Controller

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

---

## ✅ G. Register the Service

📄 `Program.cs`

```csharp
builder.Services.AddScoped<IAuthService, AuthService>();

```

---

## ✅ TL;DR Summary

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

# ✅ D. Securing Endpoints (JWT)

### 1. Add Protected Endpoint

📄 `AuthController.cs`

```csharp
[Authorize]
[HttpGet("authenticated")]
public IActionResult AuthenticatedOnlyEndpoint()
{
    if (User.Identity?.IsAuthenticated == true)
        return Ok("✅ You are authenticated");

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

# ✅ E. Role-Based Access Control

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
        return Ok("✅ You are admin");

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

## ✅ Bonus Testing Tip

Use **Postman** or **Thunder Client** with headers:

```
Authorization: Bearer <your_jwt_token>

```

Then test:

- `/api/auth/authenticated` ✅ for any logged-in user
- `/api/auth/admin-only` ✅ only if JWT has Role: Admin

---

## ✅ TL;DR: Why All This?

| Feature | Purpose |
| --- | --- |
| `Authorize` | Protect routes from anonymous access |
| JWT Config | Validates token signature, expiry, issuer, audience |
| Role Claim | Enables role-based security |
| Service Layer | Keeps Auth logic separated, clean, and testable |
| DTOs | Prevent exposing full DB entity |