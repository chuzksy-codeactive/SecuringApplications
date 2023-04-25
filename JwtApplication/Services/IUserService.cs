using JwtApplication.Dtos;
using JwtApplication.Helpers;
using Microsoft.AspNetCore.Mvc;

namespace JwtApplication.Services
{
    public interface IUserService
    {
        public Task<SuccessResponse<UserDTO>> Register(UserCreateDTO model);
        Task<SuccessResponse<UserDTO>> GetUserById(Guid userId);
        Task<PagedResponse<IEnumerable<UserDTO>>> GetAllAdminUser(ResourceParameter parameter, string name, IUrlHelper urlHelper);
        Task<SuccessResponse<bool>> UpdateUserStatus(Guid id, string status);
    }
}
