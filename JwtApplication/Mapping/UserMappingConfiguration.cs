using JwtApplication.Domain;
using JwtApplication.Dtos;
using Mapster;

namespace JwtApplication.Mapping
{
    public class UserMappingConfiguration : IRegister
    {
        public void Register(TypeAdapterConfig config)
        {
            config.NewConfig<UserDTO, User>()
                .AfterMapping((src, dest) => 
                {
                    dest.Email = src.Email.Trim().ToLower();
                    dest.UserName = src.Email.Trim().ToLower();
                    dest.SecurityStamp = Guid.NewGuid().ToString();
                });
            config.NewConfig<User, AuthDto>().TwoWays();
            config.NewConfig<User, UserDTO>();
            config.NewConfig<User, GetSetPasswordDto>()
                .AfterMapping((src, dest) =>
                {
                    dest.UserId = src.Id;
                })
                .TwoWays();
        }
    }
}
