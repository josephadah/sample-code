using System;
using System.Threading.Tasks;
using XYZ.Core.Interfaces;
using XYZ.Core.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using XYZ.API.DTOs;
using XYZ.Core.Services;
using XYZ.Core.Models.Email;
using System.Collections.Generic;

namespace XYZ.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _accountService;
        private readonly ICommonService _commonService;

        public AccountController(IAccountService accountService, ICommonService commonService)
        {
            _accountService = accountService;
            _commonService = commonService;
        }

        /// <summary>
        /// Endpoint to register on the system using the user's email
        /// </summary>
        /// <param name="model">User Registration Credentials</param>
        /// <returns>Returns an authentication response</returns>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task RegisterAsync([FromBody] UserRegistrationDto model)
        {
            var user = new User
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber,
            };

            await _accountService.RegisterWithPasswordAsync(user, model.Password);
        }

        /// <summary>
        /// Endpoint to login to the system using the user's email
        /// </summary>
        /// <param name="model">User Login Credentials</param>
        /// <returns>Returns an authentication response</returns>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<AuthenticationResponse> LoginAsync([FromBody] UserRegistrationDto model)
        {
            return await _accountService.LoginWithPasswordAsync(model.Email, model.Password);
        }

        /// <summary>
        /// Confirm user email address using token
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailDto model)
        {
            await _accountService.ConfirmEmail(model.Email, model.Token);

            return Ok();
        }

        /// <summary>
        /// Resend confirmation email to user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("resend-confirmation-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] UserRegistrationDto model)
        {
            await _accountService.ResendConfirmationEmail(model.Email);

            return Ok();
        }

        /// <summary>
        /// Confirm profile listing email 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("confirm-profile-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmProfileEmail([FromBody] ConfirmEmailDto model)
        {
            await _commonService.ConfirmProfileEmail(model.ProfileId, model.ProfileType, model.Token);

            return Ok();
        }

        /// <summary>
        /// Request password reset link
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("request-password-reset")]
        [AllowAnonymous]
        public async Task<IActionResult> RequestPasswordReset([FromBody] UserRegistrationDto model)
        {
            await _accountService.RequestPasswordReset(model.Email);

            return Ok();
        }

        /// <summary>
        /// Reset user password endpoint
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] UserRegistrationDto model)
        {
            await _accountService.ResetPassword(model.Email, model.Password, model.Token);

            return Ok();
        }
    }
}