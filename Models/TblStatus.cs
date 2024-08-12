using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblStatus
{
    public int StatusId { get; set; }

    public string StatusName { get; set; } = null!;

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdaredBy { get; set; }

    public bool MDelete { get; set; }

    public virtual ICollection<TblOrdersMain> TblOrdersMains { get; set; } = new List<TblOrdersMain>();
}
