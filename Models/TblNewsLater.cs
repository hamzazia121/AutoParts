using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblNewsLater
{
    public int NewsLaterId { get; set; }

    public string? EmailAddress { get; set; }

    public bool? IsSubcribe { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }
}
