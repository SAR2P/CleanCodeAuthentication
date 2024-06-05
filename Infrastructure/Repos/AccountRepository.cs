using Application.contract;
using Application.DTOs.Request.Account;
using Application.DTOs.Response;
using Application.DTOs.Response.Account;
using Application.Extention;
using Domain.Entity.Authentication;
using Infrastructure.Data;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Infrastructure.Repos
{
    public class AccountRepository(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager,
        IConfiguration config, SignInManager<ApplicationUser> signInManager, AppDbContext context
        ) : IAccount
    {

        #region private methods

        private async Task<ApplicationUser> FindUserByEmailAsync(string email)
        {
            return await userManager.FindByEmailAsync(email);
        }
        private async Task<IdentityRole> FindRoleByNameAsync(string roleName)
        {
            return await roleManager.FindByNameAsync(roleName);
        }

        private static string GenerateRefreshToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        }

        private async Task<string> GenerateToken(ApplicationUser user)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var userClaims = new[]
                {
                    new Claim(ClaimTypes.Name, user.Name),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Role, (await userManager.GetRolesAsync(user)).FirstOrDefault().ToString()),
                    new Claim("FullName", user.Name)
                };

                var token = new JwtSecurityToken(
                    issuer: config["Jwt:Issuer"],
                    audience: config["Jwt:Audience"],
                    claims: userClaims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: credentials
                    );
                return new JwtSecurityTokenHandler().WriteToken(token);

            }
            catch
            {
                return "token did not create";
            }
        }

        private async Task<GeneralResponse> AssignUserToRole(ApplicationUser user, IdentityRole role)
        {
            if (user == null || role == null)
            {
                return new GeneralResponse(false, "Model State Cannot be empty");
            }
            if (await FindRoleByNameAsync(role.Name) == null)
            {
                await CreateRoleAsync(role.Adapt(new CreateRoleDTO()));
            }
            IdentityResult result = await userManager.AddToRoleAsync(user, role.Name);
            string error = CheckResponse(result);
            if (!string.IsNullOrEmpty(error))
            {
                return new GeneralResponse(false, error);
            }
            else
                return new GeneralResponse(true, $"{user.Name} assigned to {role.Name} Role");

        }

        private static string CheckResponse(IdentityResult result)
        {
            if (!result.Succeeded)
            {
                var error = result.Errors.Select(_ => _.Description);
                return string.Join(Environment.NewLine, error);
            }
            return null!;
        }

        #endregion

        public async Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO Model)
        {
            if (await FindRoleByNameAsync(Model.RoleName) == null)
                return new GeneralResponse(false, "role not found");

            if (await FindUserByEmailAsync(Model.UserEmail) == null)
                return new GeneralResponse(false, "User Not Found");

            var user = await FindUserByEmailAsync(Model.UserEmail);
            var previousRole = (await userManager.GetRolesAsync(user)).FirstOrDefault();
            var removeOldRole = await userManager.RemoveFromRoleAsync(user, previousRole);
            var error = CheckResponse(removeOldRole);
            if (!string.IsNullOrEmpty(error))
                return new GeneralResponse(false, error);
            //to this section of method we deleted the old Role ^ 

            var result = await userManager.AddToRoleAsync(user, Model.RoleName);
            var response = CheckResponse(result);
            if (!string.IsNullOrEmpty(response))
                return new GeneralResponse(false, response);
            else
                return new GeneralResponse(true, "role changed");
        }

        public async Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model)
        {
            try
            {
                if (await FindUserByEmailAsync(model.EmailAddress) != null)
                    return new GeneralResponse(false, "Sorry, user is already created");

                var user = new ApplicationUser()
                {
                    Name = model.Name,
                    UserName = model.EmailAddress,
                    Email = model.EmailAddress,
                    PasswordHash = model.Password
                };

                var result = await userManager.CreateAsync(user, model.Password);
                string error = CheckResponse(result);
                if (!string.IsNullOrEmpty(error))
                    return new GeneralResponse(false, error);

                var (flag, message) = await AssignUserToRole(user, new IdentityRole() { Name = model.Role });
                //asignuserToRole method return a generalResponse that have to prop includ flage and message(we created a identityRole and Send it)

                return new GeneralResponse(flag, message);
            }
            catch (Exception ex)
            {
                return new GeneralResponse(false, ex.Message);
            }
        }

        public async Task CreateAdmin()
        {
            try
            {
                if (await FindRoleByNameAsync(Constant.Role.Admin) != null)
                    return;

                var admin = new CreateAccountDTO()
                {
                    Name = "Admin",
                    Password = "Amin@123",
                    EmailAddress = "admin@admin.com",
                    Role = Constant.Role.Admin
                };
                await CreateAccountAsync(admin);
            }
            catch (Exception)
            {

                throw;
            }
        }

        public async Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model)
        {
            try
            {
                if ((await FindRoleByNameAsync(model.Name)) == null)
                {
                    var response = await roleManager.CreateAsync(new IdentityRole(model.Name));
                    var error = CheckResponse(response);
                    if (!string.IsNullOrEmpty(error))
                        throw new Exception(error);
                    else
                        return new GeneralResponse(true, $"{model.Name} Created");

                }
                return new GeneralResponse(false, $"{model.Name} already Created");
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public async Task<IEnumerable<GetRoleDTO>> GetRolesAsync()
        {
            return (await roleManager.Roles.ToListAsync()).Adapt<IEnumerable<GetRoleDTO>>();
        }

        public async Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync()
        {
            var allUsers = await userManager.Users.ToListAsync();
            if (allUsers == null)
                return null!;

            var list = new List<GetUsersWithRolesResponseDTO>();
            foreach (var user in allUsers)
            {
                var getUserRole = (await userManager.GetRolesAsync(user)).FirstOrDefault();
                var getRoleInfo = await roleManager.Roles.FirstOrDefaultAsync(r => r.Name.ToLower() == getUserRole.ToLower());
                list.Add(new GetUsersWithRolesResponseDTO()
                {
                    Name = user.Name,
                    Email = user.Email,
                    RoleId = getRoleInfo.Id,
                    RoleName = getRoleInfo.Name
                });
            }
            return list;
        }

        public async Task<LoginResponse> LoginAccountAsync(LoginDTO model)
        {
            try
            {
                var user = await FindUserByEmailAsync(model.EmailAddress);
                if (user == null)
                    return new LoginResponse(false, "user not found, you shoud sign in...");

                SignInResult result;
                try
                {
                    result = await signInManager.CheckPasswordSignInAsync(user, model.Password, false);
                }
                catch
                {
                    return new LoginResponse(false, "Invalid credentials");
                }
                if (!result.Succeeded)
                    return new LoginResponse(false, "Invalid Credentials");

                string jwtToken = await GenerateToken(user);
                string refreshToken = GenerateRefreshToken();
                if (string.IsNullOrEmpty(jwtToken) || string.IsNullOrEmpty(refreshToken))
                    return new LoginResponse(false, "Error occured while logging in account, please contact administration");
                else
                {
                    var saveResult = await SaveRefreshToken(user.Id, refreshToken);
                    if (saveResult.Flag)
                        return new LoginResponse(true, $"{user.Name} succesfully logged in", jwtToken, refreshToken);
                    else
                        return new LoginResponse();

                }

            }
            catch (Exception ex)
            {
                return new LoginResponse(false, ex.Message);
            }
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model)
        {
            var token = await context.RefreshToken.FirstOrDefaultAsync(t => t.Token == model.Token);
            if (token == null)
                return new LoginResponse();

            var user = await userManager.FindByIdAsync(token.UserId);
            string newToken = await GenerateToken(user);
            string newRefreshToken = GenerateRefreshToken();
            var saveResult = await SaveRefreshToken(user.Id, newRefreshToken);
            if (saveResult.Flag)
                return new LoginResponse(true, $"{user.Name} Succesfuly re-logged id", newToken, newRefreshToken);
            else
                return new LoginResponse();
        }


        #region generate Token

        private async Task<GeneralResponse> SaveRefreshToken(string userId, string token)
        {
            try
            {
                var user = await context.RefreshToken.FirstOrDefaultAsync(t => t.UserId == userId);

                if (user == null)
                    context.RefreshToken.Add(new RefreshToken() { UserId = userId, Token = token });
                else
                    user.Token = token;

                await context.SaveChangesAsync();
                return new GeneralResponse(true, null!);
            }
            catch (Exception ex)
            {
                return new GeneralResponse(false, ex.Message);
            }

        }

        #endregion
    }

}
