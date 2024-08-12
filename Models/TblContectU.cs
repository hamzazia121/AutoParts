using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblContectU
{
    public int ContectUsId { get; set; }

    public string ContectUsName { get; set; } = null!;

    public string? ContectUsEmail { get; set; }

    public string ContectUsPhoneNo { get; set; } = null!;

    public string? ContectUsSubject { get; set; }

    public string? ContectUsMassage { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool Mdelete { get; set; }
}
