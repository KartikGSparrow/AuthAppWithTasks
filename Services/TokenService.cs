// Generate, validate or remove tokens

using AuthAppNew.Helpers;
using AuthAppNew.Models;
using Microsoft.EntityFrameworkCore;
using AuthAppNew.Interfaces;
using AuthAppNew.Requests;
using AuthAppNew.Responses;

namespace AuthAppNew.Services
{
    public class TokenService : ITokenService
    {
        private readonly TasksDbContext tasksDBContext;

        public TokenService(TasksDbContext tasksDBContext)
        {
            this.tasksDBContext = tasksDBContext;
        }

        public async Task<Tuple<string, string>> GenerateTokensAsync(int userId)
        {
            var accessToken = await TokenHelper.GenerateAccessToken(userId);
            var refreshToken = await TokenHelper.GenerateRefreshToken();

            var userRecord = await tasksDBContext.Users.Include(o => o.RefreshTokens).FirstOrDefaultAsync(e => e.Id == userId);

            if (userRecord is null)
            {
                return null;
            }

            var salt = PasswordHelper.GetSecureSalt();

            var refreshTokenHashed = PasswordHelper.HashUsingPbkdf2(refreshToken, salt);

            if (userRecord.RefreshTokens != null && userRecord.RefreshTokens.Any())
                await RemoveRefreshTokenAsync(userRecord);

            userRecord.RefreshTokens?.Add(new RefreshToken
            {
                ExpiryDate = DateTime.UtcNow.AddDays(7),
                Ts = DateTime.Now,
                UserId = userId,
                TokenHash = refreshTokenHashed,
                TokenSalt = Convert.ToBase64String(salt)
            });

            await tasksDBContext.SaveChangesAsync();

            var token = new Tuple<string, string>(accessToken, refreshToken);

            return token;
        }

        public async Task<bool> RemoveRefreshTokenAsync(User user)
        {
            var userRecord = await tasksDBContext.Users.Include(o => o.RefreshTokens).FirstOrDefaultAsync(e => e.Id == user.Id);

            if (userRecord is null)
                return false;

            if (userRecord.RefreshTokens != null && userRecord.RefreshTokens.Any())
            {
                var currentRefreshToken = userRecord.RefreshTokens.First();

                tasksDBContext.RefreshTokens.Remove(currentRefreshToken);
            }
            return false;
        }

        public async Task<ValidateRefreshTokenResponse> ValidateRefreshTokenAsync(RefreshTokenRequest refreshTokenRequest)
        {
            var refreshToken = await tasksDBContext.RefreshTokens.FirstOrDefaultAsync(o => o.Id == refreshTokenRequest.UserId);
            var response = new ValidateRefreshTokenResponse();
            if (refreshToken is null)
            {
                response.Success = false;
                response.Error = "Invalid session or user is already logged out.";
                response.ErrorCode = "R02";
                return response;
            }

            var refreshTokenToValidateHash = PasswordHelper.HashUsingPbkdf2(refreshTokenRequest.RefreshToken, Convert.FromBase64String(refreshToken.TokenSalt));

            if (refreshToken.TokenHash != refreshTokenToValidateHash)
            {
                response.Success = false;
                response.Error = "Invalid refresh token";
                response.ErrorCode = "R03";
                return response;
            }

            if  (refreshToken.ExpiryDate < DateTime.Now)
            {
                response.Success = false;
                response.Error = "Refresh Token is Expired";
                response.ErrorCode = "R04";
                return response;
            }

            response.Success = true;
            response.UserId = refreshToken.UserId;

            return response;
        }
    }
}
