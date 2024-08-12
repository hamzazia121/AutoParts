using AutoPartsHub.Models;

namespace AutoPartsHub._Helper
{
    public interface IMailService
    {
        Task<bool> SendAsync(MailData mailData, CancellationToken ct = default);
        Task<bool> SendMailAsync(string toAddress, string Subject, string Body);
    }
}
