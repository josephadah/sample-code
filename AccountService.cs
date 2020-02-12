using XYZ.Core.Enums;
using XYZ.Core.Helpers;
using XYZ.Core.Interfaces;
using XYZ.Core.Models;
using XYZ.Core.Models.Email;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace XYZ.Core.Services
{
    public class AccountService : IAccountService
    {
        private readonly IJwtHandler _jwtHandler;
        private readonly ICryptoService _cryptoService;
        private readonly IUserRepository _userRepository;
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        private readonly IEmailSender _emailSender;

        public AccountService(IJwtHandler jwtHandler,
                              ICryptoService cryptoService,
                              IUserRepository userRepository,
                              IConfiguration configuration,
                              IEmailSender emailSender,
                              IUserService userService)
        {
            _jwtHandler = jwtHandler;
            _cryptoService = cryptoService;
            _userRepository = userRepository;
            _configuration = configuration;
            _userService = userService;
            _emailSender = emailSender;
        }
        
        public async Task RegisterWithPasswordAsync(User model, string password, bool isMigrating = false)
        {
            await RegisterUserAsync(model, password, isMigrating);
        }

        public async Task<AuthenticationResponse> LoginWithPasswordAsync(string email, string password)
        {
            ArgumentGuard.NotNullOrWhiteSpace(email, nameof(email));
            ArgumentGuard.NotNullOrWhiteSpace(password, nameof(password));

            var user = await LoginAsync(email, password);

            var token = _jwtHandler.CreateAccessToken(user);

            return Response(user, token);
        }

        public async Task ConfirmEmail(string email, string token)
        {
            ArgumentGuard.NotNullOrWhiteSpace(email, nameof(email));
            ArgumentGuard.NotNullOrWhiteSpace(token, nameof(token));

            var user = await _userService.FindUserByEmailAsync(email.ToLower());

            if (user.IsNull()) throw new Exception("User not found");

            if (string.IsNullOrWhiteSpace(user.Token) || !user.Token.Equals(token)) throw new AppException("Invalid token");

            user.LoginProfile.EmailVerified = true;

            await _userRepository.UpdateUserAsync(user);
        }

        public async Task ResendConfirmationEmail(string email)
        {
            ArgumentGuard.NotNullOrEmpty(email, nameof(email));

            var user = await _userService.FindUserByEmailAsync(email.Trim().ToLower());

            if (user.IsNull()) return;

            await _emailSender.SendRegistrationConfirmationEmail(user, user.Token);
        }

        public async Task RequestPasswordReset(string email)
        {
            ArgumentGuard.NotNullOrEmpty(email, nameof(email));

            var userEmail = email.Trim().ToLower();
            var user = await _userService.FindUserByEmailAsync(userEmail);

            if (user.IsNull()) return;

            var resetToken = _cryptoService.CreateUniqueKey();
            user.Token = resetToken;

            await _userRepository.UpdateUserAsync(user);

            await _emailSender.SendPasswordReset(user, resetToken);
        }

        public async Task ResetPassword(string email, string password, string token)
        {
            ArgumentGuard.NotNullOrEmpty(email, nameof(email));
            ArgumentGuard.NotNullOrEmpty(password, nameof(password));
            ArgumentGuard.NotNullOrEmpty(token, nameof(token));

            var userEmail = email.Trim().ToLower();

            var user = await _userService.FindUserByEmailAsync(userEmail);

            if (user.IsNull()) throw new Exception("User Not Found");

            if (!user.Token.Equals(token)) throw new AppException("Invalid token, Request password change again");

            var salt = _cryptoService.GenerateSalt(32);
            user.LoginProfile.Salt = salt;
            user.LoginProfile.Password = _cryptoService.Hash(password, salt, 1963);

            user.LoginProfile.EmailVerified = true;

            await _userRepository.UpdateUserAsync(user);
        }

        private async Task<User> RegisterUserAsync(User user, string password, bool isMigrating = false)
        {
            ArgumentGuard.NotNull(user, nameof(user));
            ArgumentGuard.NotNullOrEmpty(user.Email, nameof(user.Email));
            ArgumentGuard.NotNullOrEmpty(user.FirstName, nameof(user.FirstName));
            ArgumentGuard.NotNullOrEmpty(user.LastName, nameof(user.LastName));

            var dbUser = await _userService.FindUserByEmailAsync(user.Email.Trim().ToLower());

            if (!dbUser.IsNull())
            {
                throw new AppException($"User With {user.Email} Already Exists");
            }

            var userRoles = new List<UserRole>();

            var roleUser = await _userRepository.GetRole(UserRoleEnum.User.ToString());
            if (roleUser.IsNull()) throw new Exception("Role not found");
            userRoles.Add(new UserRole { Role = roleUser });

            // add admin role to admin users specified in appsettings
            var admins = _configuration.GetValue<string>("Admins");
            if (admins.Contains(user.Email.ToLower()))
            {
                var roleAdmin = await _userRepository.GetRole(UserRoleEnum.Admin.ToString());
                if (roleAdmin.IsNull()) throw new Exception("Admin role not found in db");
                userRoles.Add(new UserRole { Role = roleAdmin });
            }

            // add admin role to admin users specified in appsettings
            var superAdmins = _configuration.GetValue<string>("SuperAdmins");
            if (superAdmins.Contains(user.Email.ToLower()))
            {
                var roleSuperAdmin = await _userRepository.GetRole(UserRoleEnum.SuperAdmin.ToString());
                if (roleSuperAdmin.IsNull()) throw new Exception("Super Admin role not found in db");
                userRoles.Add(new UserRole { Role = roleSuperAdmin });
            }

            var newUser = new User
            {
                Email = user.Email.Trim().ToLower(),
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber,
                InformationPreference = user.InformationPreference,
                PhotoUrl = user.PhotoUrl,
                CreatedAt = DateTime.UtcNow,
                UserRoles = userRoles
            };

            if (!string.IsNullOrEmpty(password))
            {
                var loginProfile = new LoginProfile();
                var salt = _cryptoService.GenerateSalt(32);
                loginProfile.Salt = salt;
                loginProfile.Password = _cryptoService.Hash(password, salt, 1963);

                var loginProfileId = await _userRepository.AddLoginProfileAsync(loginProfile);

                newUser.LoginProfileId = loginProfileId;

                var resUser = await _userRepository.AddUserAsync(newUser);

                var emailConfirmationToken = _cryptoService.CreateUniqueKey();

                resUser.Token = emailConfirmationToken;

                await _userRepository.UpdateUserAsync(resUser);

                if (isMigrating)
                {
                    // send a migration notice email with link to change their password
                    await _emailSender.SendMigrationEmail(resUser, emailConfirmationToken);
                }
                else
                {
                    await _emailSender.SendRegistrationConfirmationEmail(resUser, emailConfirmationToken);
                }

                return resUser;
            }
            else
            {
                return await _userRepository.AddUserAsync(newUser);
            }
        }

        private async Task<User> LoginAsync(string email, string password)
        {
            var userEmail = email.Trim().ToLower();

            var dbUser = await _userRepository.FindUserByEmailAsync(userEmail);

            if (dbUser.IsNull())
            {
                throw new AppException($"Email or Password is incorrect");
            }

            var hashedPassword = _cryptoService.Hash(password, dbUser.LoginProfile.Salt, 1963);

            if (dbUser.LoginProfile.Password != hashedPassword)
            {
                throw new AppException("Email or Password is incorrect");
            }

            if (!dbUser.LoginProfile.EmailVerified)
            {
                throw new AppException($"email has not been verified. Check inbox to verify.");
            }

            return dbUser;
        }

        private AuthenticationResponse Response(User user, string token)
        {
            return new AuthenticationResponse
            {
                Token = token,
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                PhotoUrl = user.PhotoUrl,
                Roles = user.UserRoles
            };
        }
    }
}
