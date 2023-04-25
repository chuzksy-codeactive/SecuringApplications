using JwtApplication.Data;
using JwtApplication.Domain;
using JwtApplication.Dtos;
using JwtApplication.Enums;
using JwtApplication.Helpers;
using MapsterMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net;

namespace JwtApplication.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<Role> _roleManager;
        private readonly IMapper _mapper;
        private readonly AppDbContext _dbContext;

        public UserService(AppDbContext dbContext,
            IMapper mapper,
            RoleManager<Role> roleManager,
            UserManager<User> userManager)
        {
            _dbContext = dbContext;
            _mapper = mapper;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        public async Task<PagedResponse<IEnumerable<UserDTO>>> GetAllAdminUser(ResourceParameter parameter, string name, IUrlHelper urlHelper)
        {
            var userQuery = _dbContext.Users as IQueryable<User>;

            if (!string.IsNullOrWhiteSpace(parameter.Search))
            {
                var searchTerm = parameter.Search.Trim().ToLower();
                userQuery = userQuery.Where(x => x.FirstName.Contains(searchTerm) ||
                    x.LastName.Contains(searchTerm) ||
                    x.Email.Contains(searchTerm) ||
                    x.UserName.Contains(searchTerm));
            }
            var userRoleQuery = _dbContext.UserRoles as IQueryable<UserRole>;
            var rolesQuery = _roleManager.Roles;

            var usersList = from user in userQuery
                            join uRoles in userRoleQuery on user.Id equals uRoles.UserId
                            join role in rolesQuery on uRoles.RoleId equals role.Id
                            where role.NormalizedName == ERole.ADMIN.ToString()
                            select new UserDTO
                            {
                                Id = user.Id,
                                FirstName = user.FirstName,
                                LastName = user.LastName,
                                PhoneNumber = user.PhoneNumber,
                                Email = user.Email,
                                Status = user.Status,
                                IsActive = user.IsActive,
                                Verified = user.Verified,
                                Role = role.Name
                            };

            var users = await PagedList<UserDTO>.Create(usersList, parameter.PageNumber,
                parameter.PageSize,
                parameter.Sort);
            var page = PageUtility<UserDTO>.CreateResourcePageUrl(parameter, name, users, urlHelper);

            return new PagedResponse<IEnumerable<UserDTO>>
            {
                Message = "Data retrieved successfully",
                Data = users,
                Meta = new Meta
                {
                    Pagination = page
                }
            };
        }

        public async Task<SuccessResponse<UserDTO>> GetUserById(Guid userId)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());

            if (user == null)
                throw new RestException(HttpStatusCode.NotFound, "User record not found");

            var userResponse = _mapper.Map<UserDTO>(user);

            return new SuccessResponse<UserDTO>
            {
                Message = "Data retrieved successfully",
                Data = userResponse
            };
        }

        public async Task<SuccessResponse<UserDTO>> Register(UserCreateDTO model)
        {
            var email = model.Email.Trim().ToLower();
            var emailExist = await _dbContext.Users.FirstOrDefaultAsync(x => x.Email == email);

            if (emailExist is not null)
                throw new RestException(HttpStatusCode.BadRequest, "Email address already exists.");

            var user = _mapper.Map<User>(model);
            user.Status = EUserStatus.PENDING.ToString();
            user.IsActive = false;
            user.Verified = false;
            user.EmailConfirmed = false;

            var result = await _userManager.CreateAsync(user, "Password@@1");
            if (!result.Succeeded)
                throw new RestException(HttpStatusCode.InternalServerError, "Internal server error");

            await _userManager.AddToRoleAsync(user, ERole.ADMIN.ToString());

            var token = CustomToken.GenerateRandomString(128);
            var tokenEntity = new Token
            {
                UserId = user.Id,
                Value = token,
                TokenType = ETokenType.InviteUser.ToString()
            };

            await _dbContext.Tokens.AddAsync(tokenEntity);
            await _dbContext.SaveChangesAsync();

            var userResponse = _mapper.Map<UserDTO>(user);

            //Send email notification to user
            //string emailLink = $"{_configuration["CLIENT_URL"]}/user-signup?token={token}";

            return new SuccessResponse<UserDTO>
            {
                Data = userResponse
            };
        }

        public async Task<SuccessResponse<bool>> UpdateUserStatus(Guid id, string status)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());

            if (user == null)
                throw new RestException(HttpStatusCode.NotFound, "This user does not exist");

            var role = ERole.SUPERADMIN.ToString();
            if (await _userManager.IsInRoleAsync(user, role))
                throw new RestException(HttpStatusCode.BadRequest, "The user status cannot be changed");

            var message = status.ToLower() == EUserStatus.DEACTIVATE.ToString().ToLower()
                ? "Deactivated" : status.ToLower() == EUserStatus.ACTIVE.ToString().ToLower()
                ? "Activated" : throw new RestException(HttpStatusCode.BadRequest, "This value is not a valid");

            user.IsActive = status.ToLower() == EUserStatus.ACTIVE.ToString().ToLower();
            user.Status = message.ToUpper();
            user.UpdatedAt = DateTime.Now;
            await _userManager.UpdateAsync(user);

            await _dbContext.SaveChangesAsync();

            return new SuccessResponse<bool>
            {
                Data = true,
                Message = $"User has been {message} successfully"
            };
        }
    }
}
