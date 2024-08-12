using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblPayment
{
    public int PaymentId { get; set; }

    public decimal PaymentAmount { get; set; }

    public string PaymentType { get; set; } = null!;

    public string? Url { get; set; }

    public int UserId { get; set; }

    public int? PaymentTokenId { get; set; }

    public int? PaymentLogId { get; set; }

    public string? PaymentStatus { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? Updatedat { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual TblPaymentLog? PaymentLog { get; set; }

    public virtual TblUser User { get; set; } = null!;
}
