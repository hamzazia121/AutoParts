using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblProvince
{
    public int ProvinceId { get; set; }

    public string? ProvinceName { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool Mdelete { get; set; }

    public virtual ICollection<TblOrdersMain> TblOrdersMains { get; set; } = new List<TblOrdersMain>();
}
