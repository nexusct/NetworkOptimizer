using System.Text.Json.Serialization;

namespace NetworkOptimizer.UniFi.Models;

/// <summary>
/// Response from GET /api/s/{site}/stat/event
/// Represents a site event from the controller's event log (client joins/leaves,
/// device state changes, admin actions, etc.). Field presence varies widely by event
/// type - everything beyond Id is optional.
/// </summary>
public class UniFiSiteEvent
{
    [JsonPropertyName("_id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Event type key (e.g. "EVT_LU_Connected", "EVT_AP_Restarted", "EVT_AD_Login").
    /// </summary>
    [JsonPropertyName("key")]
    public string? Key { get; set; }

    /// <summary>
    /// Human-readable event message.
    /// </summary>
    [JsonPropertyName("msg")]
    public string? Msg { get; set; }

    /// <summary>
    /// Event timestamp. Most controller versions return Unix epoch MILLISECONDS here
    /// (unlike the seconds used elsewhere in the API).
    /// </summary>
    [JsonPropertyName("time")]
    public long Time { get; set; }

    /// <summary>
    /// ISO-8601 representation of <see cref="Time"/> when the controller provides it.
    /// </summary>
    [JsonPropertyName("datetime")]
    public string? Datetime { get; set; }

    [JsonPropertyName("site_id")]
    public string? SiteId { get; set; }

    /// <summary>
    /// Originating subsystem ("wlan", "lan", "wan", "adm", ...).
    /// </summary>
    [JsonPropertyName("subsystem")]
    public string? Subsystem { get; set; }

    /// <summary>
    /// True when the event was triggered by an admin action (login, config change).
    /// </summary>
    [JsonPropertyName("is_admin")]
    [JsonConverter(typeof(FlexibleNullableBoolConverter))]
    public bool? IsAdmin { get; set; }

    /// <summary>Admin username for admin-triggered events.</summary>
    [JsonPropertyName("admin")]
    public string? Admin { get; set; }

    /// <summary>MAC of the AP this event relates to, when applicable.</summary>
    [JsonPropertyName("ap")]
    public string? Ap { get; set; }

    /// <summary>MAC of the gateway this event relates to, when applicable.</summary>
    [JsonPropertyName("gw")]
    public string? Gw { get; set; }

    /// <summary>MAC of the switch this event relates to, when applicable.</summary>
    [JsonPropertyName("sw")]
    public string? Sw { get; set; }

    /// <summary>MAC of the user/client device this event relates to.</summary>
    [JsonPropertyName("user")]
    public string? User { get; set; }

    /// <summary>Alternate client MAC field seen on some event types.</summary>
    [JsonPropertyName("client")]
    public string? Client { get; set; }

    /// <summary>Hostname of the client, when resolved.</summary>
    [JsonPropertyName("hostname")]
    public string? Hostname { get; set; }

    /// <summary>SSID for wireless client events.</summary>
    [JsonPropertyName("ssid")]
    public string? Ssid { get; set; }

    /// <summary>Radio band for wireless events ("ng", "na", "6e").</summary>
    [JsonPropertyName("radio")]
    public string? Radio { get; set; }

    /// <summary>Channel for wireless events.</summary>
    [JsonPropertyName("channel")]
    [JsonConverter(typeof(FlexibleIntConverter))]
    public int? Channel { get; set; }

    /// <summary>Session duration (seconds) for disconnect events.</summary>
    [JsonPropertyName("duration")]
    [JsonConverter(typeof(FlexibleIntConverter))]
    public int? Duration { get; set; }

    /// <summary>Bytes transferred for client session events.</summary>
    [JsonPropertyName("bytes")]
    [JsonConverter(typeof(FlexibleLongConverter))]
    public long? Bytes { get; set; }
}
