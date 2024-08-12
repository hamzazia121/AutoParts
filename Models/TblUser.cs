using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblUser
{
    public int UserId { get; set; }

    public string UserName { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string PhoneNumber { get; set; } = null!;

    public string Password { get; set; } = null!;

    public int? RollId { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual TblRoll? Roll { get; set; }

    public virtual ICollection<TblOrdersMain> TblOrdersMains { get; set; } = new List<TblOrdersMain>();

    public virtual ICollection<TblPayment> TblPayments { get; set; } = new List<TblPayment>();
}
