using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblPaymentLog
{
    public int PaymentLogId { get; set; }

    public string? PaymentUniqueToken { get; set; }

    public string? Token { get; set; }

    public string? Email { get; set; }

    public string? Response { get; set; }

    public string? Status { get; set; }

    public string? Remarks { get; set; }

    public string PaymentMethods { get; set; } = null!;

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public DateTime? Updatedby { get; set; }

    public bool Mdelete { get; set; }

    public virtual ICollection<TblPayment> TblPayments { get; set; } = new List<TblPayment>();
}
