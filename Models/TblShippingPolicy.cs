using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblShippingPolicy
{
    public int ShipingId { get; set; }

    public decimal PolicyAmount { get; set; }

    public bool? IsLifeTime { get; set; }

    public DateTime? PolicyStatsDate { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }
}
