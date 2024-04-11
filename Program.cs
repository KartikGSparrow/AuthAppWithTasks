using AuthAppNew.Helpers;
using AuthAppNew.Interfaces;
using AuthAppNew.Models;
using AuthAppNew.Requests;
using AuthAppNew.Responses;
using AuthAppNew.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

const string AllowAllHeadersPolicy = "AllowAllHeadersPolicy";

builder.Services.AddCors(options =>
{
    options.AddPolicy(AllowAllHeadersPolicy,
        builder =>
        {
            builder.WithOrigins("http://localhost:4200")
                    .AllowAnyMethod()
                   .AllowAnyHeader();
        });
});

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<TasksDbContext>(options => options.UseSqlServer
(builder.Configuration.GetConnectionString("TasksDbConnectionString")));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = TokenHelper.Issuer,
                ValidAudience = TokenHelper.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(TokenHelper.Secret)),
                ClockSkew = TimeSpan.Zero
            };

        });

builder.Services.AddAuthorization();

builder.Services.AddTransient<ITokenService, TokenService>();
builder.Services.AddTransient<IUserService, UserService>();
builder.Services.AddTransient<ITaskService, TaskService>();

var app = builder.Build();
app.UseCors(AllowAllHeadersPolicy);

app.MapPost("api/users/login", async (LoginRequest loginRequest, IUserService userService) =>
{
    if (loginRequest is null || string.IsNullOrEmpty(loginRequest.Email) || string.IsNullOrEmpty(loginRequest.Password))
    {
        return Results.BadRequest(new TokenResponse
        {
            Error = "Missing login details",
            ErrorCode = "L01"
        });
    }

    var loginResponse = await userService.LoginAsync(loginRequest);

    if (!loginResponse.Success)
    {
        return Results.Unauthorized();
    }

    return Results.Ok(loginResponse);
});

app.MapPost("/api/users/refresh_token", async (RefreshTokenRequest refreshTokenRequest, ITokenService tokenService) =>
{
    if (refreshTokenRequest is null || string.IsNullOrEmpty(refreshTokenRequest.RefreshToken) || refreshTokenRequest.UserId == 0)
    {
        return Results.BadRequest(new TokenResponse
        {
            Error = "Missing token refresh details",
            ErrorCode = "R01"
        });
    }
    var validRefreshTokenResponse = await tokenService.ValidateRefreshTokenAsync(refreshTokenRequest);

    if (!validRefreshTokenResponse.Success)
    {
        return Results.UnprocessableEntity(validRefreshTokenResponse);
    }

    var tokenResponse = await tokenService.GenerateTokensAsync(validRefreshTokenResponse.UserId);

    return Results.Ok(new { AccessToken = tokenResponse.Item1, RefreshToken = tokenResponse.Item2 });
});

app.MapPost("api/users/signup", async (SignupRequest signupRequest, IUserService userService) =>
{
    if (signupRequest == null)
    {
        return Results.BadRequest();
    }

    var signupResponse = await userService.SignupAsync(signupRequest);

    if (!signupResponse.Success)
    {
        return Results.UnprocessableEntity(signupResponse);
    }

    return Results.Ok(signupResponse.Email);
});

app.MapPost("api/users/logout", async (HttpContext httpContext, IUserService userService, ITaskService taskService) =>
{
    var userIdClaim = httpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (userIdClaim == null || !int.TryParse(userIdClaim, out int userId))
        return Results.BadRequest();

    var logout = await userService.LogoutAsync(userId);

    if (!logout.Success)
        return Results.UnprocessableEntity(logout);
    return Results.Ok();
}).RequireAuthorization();

app.MapGet("/api/tasks", async (HttpContext httpContext, ITaskService taskService) =>
{
    var userIdClaim = httpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (userIdClaim == null || !int.TryParse(userIdClaim, out int userId))
        return Results.BadRequest();

    var getTasksResponse = await taskService.GetTasks(userId);

    if (!getTasksResponse.Success)
        return Results.UnprocessableEntity(getTasksResponse);

    var tasksResponse = getTasksResponse.Tasks.Select(o => new TaskResponse { Id = o.Id, IsCompleted = o.IsCompleted, Name = o.Name, Ts = o.Ts });

    return Results.Ok(tasksResponse);
}).RequireAuthorization();

app.MapPost("/api/tasks", async (TaskRequest taskRequest, HttpContext httpContext, ITaskService taskService) =>
{
    var userIdClaim = httpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (userIdClaim is null || !int.TryParse(userIdClaim, out int userId))
        return Results.BadRequest();
    var task = new AuthAppNew.Models.Task { IsCompleted = taskRequest.IsCompleted, Ts = taskRequest.Ts, Name = taskRequest.Name, UserId = userId };
    var saveTaskResponse = await taskService.SaveTask(task);

    if (!saveTaskResponse.Success)
    {
        return Results.UnprocessableEntity(saveTaskResponse);
    }

    var taskResponse = new TaskResponse { Id = saveTaskResponse.Task.Id, IsCompleted = saveTaskResponse.Task.IsCompleted, Name = saveTaskResponse.Task.Name, Ts = saveTaskResponse.Task.Ts };

    return Results.Ok(taskResponse);
}).RequireAuthorization();

app.MapDelete("/api/tasks/{id}", async (int id, HttpContext httpContext, ITaskService taskService) =>
{
    var userIdClaim = httpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (userIdClaim == null || !int.TryParse(userIdClaim, out int userId))
        return Results.BadRequest();
    var deleteTaskResponse = await taskService.DeleteTask(id, userId);
    if (!deleteTaskResponse.Success)
    {
        return Results.UnprocessableEntity(deleteTaskResponse);
    }

    return Results.Ok(deleteTaskResponse.TaskId);
}).RequireAuthorization();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.Run();