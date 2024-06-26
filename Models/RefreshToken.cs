﻿// <auto-generated> This file has been auto generated by EF Core Power Tools. </auto-generated>
#nullable disable
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace AuthAppNew.Models;

[Table("RefreshToken")]
public partial class RefreshToken
{
    [Key]
    public int Id { get; set; }

    public int UserId { get; set; }

    [Required]
    [StringLength(1000)]
    public string TokenHash { get; set; }

    [Required]
    [StringLength(50)]
    public string TokenSalt { get; set; }

    [Column("TS", TypeName = "smalldatetime")]
    public DateTime Ts { get; set; }

    [Column(TypeName = "smalldatetime")]
    public DateTime ExpiryDate { get; set; }

    [ForeignKey("UserId")]
    [InverseProperty("RefreshTokens")]
    public virtual User User { get; set; }
}