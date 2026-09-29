using System.Text.Json.Serialization;

namespace NetworkOptimizer.UniFi.Models;

/// <summary>
/// Response from GET /api/s/{site}/stat/alarm
/// Represents an alarm raised by the controller (e.g. device disconnected, rogue AP
/// detected, IPS block). GET stat/alarm returns unarchived alarms; archived ones require
/// a POST with {"archived": true}.
/// </summary>
public class UniFiAlarm
{
    [JsonPropertyName("_id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Alarm type key (e.g. "EVT_AP_Lost_Contact", "EVT_IPS_IpsAlert").
    /// </summary>
    [JsonPropertyName("key")]
    public string? Key { get; set; }

    /// <summary>
    /// Human-readable alarm message.
    /// </summary>
    [JsonPropertyName("msg")]
    public string? Msg { get; set; }

    /// <summary>
    /// Alarm timestamp. Most controller versions return Unix epoch MILLISECONDS here
    /// (unlike the seconds used elsewhere in the API).
    /// </summary>
    [JsonPropertyName("time")]
    public long Time { get; set; }

    /// <summary>
    /// ISO-8601 representation of <see cref="Time"/> when the controller provides it.
    /// </summary>
    [JsonPropertyName("datetime")]
    public string? Datetime { get; set; }

    /// <summary>
    /// Whether the alarm has been archived (dismissed) by an admin.
    /// </summary>
    [JsonPropertyName("archived")]
    [JsonConverter(typeof(FlexibleNullableBoolConverter))]
    public bool? Archived { get; set; }

    /// <summary>
    /// Originating subsystem ("wlan", "lan", "wan", "ips", ...).
    /// </summary>
    [JsonPropertyName("subsystem")]
    public string? Subsystem { get; set; }

    /// <summary>
    /// True for "bad news" alarms (device lost, intrusion) vs informational ones.
    /// </summary>
    [JsonPropertyName("is_negative")]
    [JsonConverter(typeof(FlexibleNullableBoolConverter))]
    public bool? IsNegative { get; set; }

    [JsonPropertyName("site_id")]
    public string? SiteId { get; set; }

    /// <summary>MAC of the AP this alarm relates to, when applicable.</summary>
    [JsonPropertyName("ap")]
    public string? Ap { get; set; }

    /// <summary>MAC of the gateway this alarm relates to, when applicable.</summary>
    [JsonPropertyName("gw")]
    public string? Gw { get; set; }

    /// <summary>MAC of the switch this alarm relates to, when applicable.</summary>
    [JsonPropertyName("sw")]
    public string? Sw { get; set; }

    /// <summary>MAC of the client/user this alarm relates to, when applicable.</summary>
    [JsonPropertyName("mac")]
    public string? Mac { get; set; }

    /// <summary>Hostname associated with the alarm subject, when known.</summary>
    [JsonPropertyName("host")]
    public string? Host { get; set; }
}
