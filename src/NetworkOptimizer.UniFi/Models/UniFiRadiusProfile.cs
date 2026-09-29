using System.Text.Json.Serialization;

namespace NetworkOptimizer.UniFi.Models;

/// <summary>
/// Response from GET /api/s/{site}/rest/radiusprofile
/// Represents a RADIUS profile used for 802.1X authentication on WLANs and switch ports.
/// Field availability varies by controller/firmware version - everything beyond Id and
/// Name is optional.
/// </summary>
public class UniFiRadiusProfile
{
    [JsonPropertyName("_id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("site_id")]
    public string? SiteId { get; set; }

    /// <summary>
    /// RADIUS authentication servers tried in order.
    /// </summary>
    [JsonPropertyName("auth_servers")]
    public List<UniFiRadiusServer>? AuthServers { get; set; }

    /// <summary>
    /// Whether RADIUS accounting is enabled for this profile.
    /// Some firmware versions use <see cref="UseAccounting"/> instead.
    /// </summary>
    [JsonPropertyName("accounting_enabled")]
    [JsonConverter(typeof(FlexibleNullableBoolConverter))]
    public bool? AccountingEnabled { get; set; }

    /// <summary>
    /// Legacy/alternate accounting toggle seen on some controller versions.
    /// </summary>
    [JsonPropertyName("use_accounting")]
    [JsonConverter(typeof(FlexibleNullableBoolConverter))]
    public bool? UseAccounting { get; set; }

    /// <summary>
    /// RADIUS accounting servers (when accounting is enabled).
    /// </summary>
    [JsonPropertyName("acct_servers")]
    public List<UniFiRadiusServer>? AcctServers { get; set; }

    /// <summary>
    /// Whether interim accounting updates are sent while a session is active.
    /// </summary>
    [JsonPropertyName("interim_update_enabled")]
    [JsonConverter(typeof(FlexibleNullableBoolConverter))]
    public bool? InterimUpdateEnabled { get; set; }

    /// <summary>
    /// Interval (seconds) between interim accounting updates.
    /// </summary>
    [JsonPropertyName("interim_update_interval")]
    [JsonConverter(typeof(FlexibleIntConverter))]
    public int? InterimUpdateInterval { get; set; }

    /// <summary>
    /// Whether RADIUS-assigned VLANs (Tunnel-Private-Group-ID) are honored.
    /// </summary>
    [JsonPropertyName("vlan_enabled")]
    [JsonConverter(typeof(FlexibleNullableBoolConverter))]
    public bool? VlanEnabled { get; set; }

    /// <summary>
    /// VLAN assignment mode for WLANs ("disabled", "required", "optional").
    /// </summary>
    [JsonPropertyName("vlan_wlan_mode")]
    public string? VlanWlanMode { get; set; }
}

/// <summary>
/// A single RADIUS authentication or accounting server entry.
/// </summary>
public class UniFiRadiusServer
{
    [JsonPropertyName("ip")]
    public string? Ip { get; set; }

    [JsonPropertyName("port")]
    [JsonConverter(typeof(FlexibleIntConverter))]
    public int? Port { get; set; }

    /// <summary>
    /// Shared secret. SENSITIVE: depending on controller version this may be masked or
    /// returned in plaintext - treat as a credential either way and never log it.
    /// </summary>
    [JsonPropertyName("xsecret")]
    public string? Xsecret { get; set; }
}
