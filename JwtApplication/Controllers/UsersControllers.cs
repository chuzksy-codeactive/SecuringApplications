using JwtApplication.Dtos;
using JwtApplication.Helpers;
using JwtApplication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtApplication.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        /// <summary>
        /// Endpoint to get a user
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("{id}")]
        [ProducesResponseType(typeof(SuccessResponse<UserDTO>), 200)]
        public async Task<IActionResult> GetUserById(Guid id)
        {
            var response = await _userService.GetUserById(id);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to get all admin users
        /// </summary>

        /// <returns></returns>
        /// 
        [Authorize(Roles = "SUPERADMIN")]
        [HttpGet("admins")]
        [ProducesResponseType(typeof(PagedResponse<IEnumerable<UserDTO>>), 200)]
        public async Task<IActionResult> GetAllUsers([FromQuery] ResourceParameter parameter)
        {
            var response = await _userService.GetAllAdminUser(parameter, nameof(GetAllUsers), Url);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to register a new user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "SUPERADMIN")]
        [HttpPost]
        [Route("register")]
        [ProducesResponseType(typeof(SuccessResponse<UserDTO>), 200)]
        public async Task<IActionResult> RegisterUser([FromBody] UserCreateDTO model)
        {
            var response = await _userService.Register(model);
            return Ok(response);
        }

        // <summary>Endpoint to change admin users status</summary>
        /// <param name="id"></param>
        /// <param name="status"></param>
        /// <returns></returns>
        /// 
        [Authorize(Roles = "SUPERADMIN")]
        [HttpPost("admin/status")]
        [ProducesResponseType(typeof(SuccessResponse<bool>), 200)]
        public async Task<IActionResult> UpdateUserStatus(Guid id, string status)
        {
            var response = await _userService.UpdateUserStatus(id, status);

            return Ok(response);
        }
    }
}
