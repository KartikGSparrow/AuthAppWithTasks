using AuthAppNew.Helpers;
using AuthAppNew.Models;
using AuthAppNew.Requests;
using Microsoft.EntityFrameworkCore;
using AuthAppNew.Interfaces;
using AuthAppNew.Responses;

namespace AuthAppNew.Services
{
    public class UserService : IUserService
    {
        private readonly TasksDbContext tasksDBContext;
        private readonly ITokenService tokenService;

        public UserService(TasksDbContext tasksDBContext, ITokenService tokenService)
        {
            this.tasksDBContext = tasksDBContext;
            this.tokenService = tokenService;
        }

        public async Task<TokenResponse> LoginAsync(LoginRequest loginRequest)
        {
            var user = tasksDBContext.Users.SingleOrDefault(user => user.Email == loginRequest.Email);

            if (user is null)
            {
                return new TokenResponse
                {
                    Success = false,
                    Error = "Email not found",
                    ErrorCode = "L02"
                };
            }
            var passwordHash = PasswordHelper.HashUsingPbkdf2(loginRequest.Password, Convert.FromBase64String(user.PasswordSalt));

            if (user.Password != passwordHash)
            {
                return new TokenResponse
                {
                    Success = false,
                    Error = "Invalid Password",
                    ErrorCode = "L03"
                };
            }
            var token = await System.Threading.Tasks.Task.Run(() => tokenService.GenerateTokensAsync(user.Id));

            return new TokenResponse
            {
                Success = true,
                AccessToken = token.Item1,
                RefreshToken = token.Item2
            };
        }

        public async Task<LogoutResponse> LogoutAsync(int userId)
        {
            var refreshToken = await tasksDBContext.RefreshTokens.FirstOrDefaultAsync(o => o.UserId == userId);
            if (refreshToken is null)
                return new LogoutResponse { Success = true };

            tasksDBContext.RefreshTokens.Remove(refreshToken);
            var saveResponse = await tasksDBContext.SaveChangesAsync();

            if (saveResponse >= 0)
                return new LogoutResponse { Success = true };

            return new LogoutResponse
            {
                Success = false,
                Error = "Unable to logout user",
                ErrorCode = "L04"
            };
        }

        public async Task<SignupResponse> SignupAsync(SignupRequest signupRequest)
        {
            var existingUser = await tasksDBContext.Users.SingleOrDefaultAsync(user => user.Email == signupRequest.Email);
            if (existingUser != null)
            {
                return new SignupResponse
                {
                    Success = false,
                    Error = "User already exists with the same email!",
                    ErrorCode = "S02"
                };
            }

            if (signupRequest.Password != signupRequest.ConfirmPassword)
            {
                return new SignupResponse
                {
                    Success = false,
                    Error = "Passwords do not match",
                    ErrorCode = "S03"
                };
            }
            if (signupRequest.Password.Length <= 7)
            {
                return new SignupResponse
                {
                    Success = false,
                    Error = "Password is weak",
                    ErrorCode = "S04"
                };
            }

            var salt = PasswordHelper.GetSecureSalt();
            var passwordHash = PasswordHelper.HashUsingPbkdf2(signupRequest.Password, salt);

            var user = new User
            {
                Email = signupRequest.Email,
                Password = passwordHash,
                PasswordSalt = Convert.ToBase64String(salt),
                FirstName = signupRequest.FirstName,
                LastName = signupRequest.LastName,
                Ts = signupRequest.Ts,
                Active = true
            };

            await tasksDBContext.Users.AddAsync(user);
            var saveResponse = await tasksDBContext.SaveChangesAsync();

            if (saveResponse >= 0)
                return new SignupResponse { Success = true, Email = user.Email };

            return new SignupResponse
            {
                Success = false,
                Error = "Unable to save the user",
                ErrorCode = "S05"
            };
        }
    }
}
