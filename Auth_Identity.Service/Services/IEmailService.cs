using Auth_Identity.Service.Models;

namespace Auth_Identity.Service.Services;

public interface IEmailService
{
    void SendEmail(Message message);
}
