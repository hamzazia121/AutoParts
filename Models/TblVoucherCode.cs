using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblVoucherCode
{
    public int VoucherId { get; set; }

    public string VoucherText { get; set; } = null!;

    public decimal VoucherDiscount { get; set; }

    public bool? Ispercentage { get; set; }

    public bool? IsUsed { get; set; }

    public bool? IsExpired { get; set; }

    public DateTime? VoucherExpireDate { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpadetedBy { get; set; }

    public bool Mdelete { get; set; }
}
