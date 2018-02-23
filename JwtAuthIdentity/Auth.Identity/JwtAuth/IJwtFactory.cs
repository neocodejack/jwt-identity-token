using System.Security.Claims;
using System.Threading.Tasks;

namespace Auth.Identity.Jwt
{
    public interface IJwtFactory
    {
        Task<string> CreateEncodedToken(string userName, ClaimsIdentity identity);
        ClaimsIdentity CreateClaimsIdentity(string userName, string id);
    }
}
