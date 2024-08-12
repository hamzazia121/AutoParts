using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblCity
{
    public int CityId { get; set; }

    public string CityName { get; set; } = null!;

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? Updatedby { get; set; }

    public bool Mdelete { get; set; }

    public virtual ICollection<TblOrdersMain> TblOrdersMains { get; set; } = new List<TblOrdersMain>();
}
