using System.Text.Json.Serialization;

namespace NetworkOptimizer.UniFi.Models;

/// <summary>
/// Response from GET /api/s/{site}/rest/apgroup
/// Represents an AP group - a set of access points that broadcast a shared set of WLANs.
/// Resolves the <c>ap_group_ids</c> references on UniFiWlanConfig when
/// <c>ap_group_mode != "all"</c>.
/// </summary>
public class UniFiApGroup
{
    [JsonPropertyName("_id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("site_id")]
    public string? SiteId { get; set; }

    /// <summary>
    /// MAC addresses of the APs belonging to this group.
    /// </summary>
    [JsonPropertyName("device_macs")]
    public List<string>? DeviceMacs { get; set; }

    /// <summary>
    /// True for the built-in "Default" group which cannot be deleted.
    /// </summary>
    [JsonPropertyName("attr_no_delete")]
    [JsonConverter(typeof(FlexibleNullableBoolConverter))]
    public bool? AttrNoDelete { get; set; }

    /// <summary>
    /// Hidden identifier used internally by the controller for built-in groups.
    /// </summary>
    [JsonPropertyName("attr_hidden_id")]
    public string? AttrHiddenId { get; set; }
}
