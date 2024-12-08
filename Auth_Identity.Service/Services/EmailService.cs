using Auth_Identity.Service.Models;
using MimeKit;
using MailKit.Net.Smtp;

namespace Auth_Identity.Service.Services;

public class EmailService : IEmailService
{
    private readonly EmailConfiguration _emailConfiguration;

    public EmailService(EmailConfiguration configuration)
    {
        _emailConfiguration = configuration;
    }

    public void SendEmail(Message message)
    {
        var emailMessage = CreateEmailMessage(message);
        Send(emailMessage);
    }

    private void Send(object emailMessage)
    {
        throw new NotImplementedException();
    }

    private MimeMessage CreateEmailMessage(Message message)
    {
        var emailMessage = new MimeMessage();
        emailMessage.From.Add(new MailboxAddress("email", _emailConfiguration.From));
        emailMessage.To.AddRange(message.To);
        emailMessage.Subject = message.Subject;
        emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = message.Content };

        return emailMessage;
    }

    private void Send(MimeMessage message)
    {
        using var client = new SmtpClient();
        try
        {
            client.Connect(_emailConfiguration.SmtpServer, _emailConfiguration.Port, true);
            client.AuthenticationMechanisms.Remove("XOAUTH2");
            client.Authenticate(_emailConfiguration.Username, _emailConfiguration.Password);

            client.Send(message);
        }
        catch (Exception ex)
        {
            // log the error message and throw exception
            throw;
        }
        finally
        {
            client.Disconnect(true);
            client.Dispose();
        }
    }
}
