using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetworkOptimizer.UniFi.Models;

/// <summary>
/// Response entry from POST /api/s/{site}/stat/dpi
/// Represents Deep Packet Inspection traffic totals per application (type "by_app") or
/// per category (type "by_cat"). App/category numbers reference the controller's DPI
/// fingerprint tables; resolution to names is a separate concern.
/// </summary>
public class UniFiDpiStat
{
    /// <summary>
    /// Application ID (present when grouping by app).
    /// </summary>
    [JsonPropertyName("app")]
    [JsonConverter(typeof(FlexibleIntConverter))]
    public int? App { get; set; }

    /// <summary>
    /// Category ID (present for both by_app and by_cat groupings).
    /// </summary>
    [JsonPropertyName("cat")]
    [JsonConverter(typeof(FlexibleIntConverter))]
    public int? Cat { get; set; }

    [JsonPropertyName("rx_bytes")]
    [JsonConverter(typeof(FlexibleNullableLongConverter))]
    public long? RxBytes { get; set; }

    [JsonPropertyName("tx_bytes")]
    [JsonConverter(typeof(FlexibleNullableLongConverter))]
    public long? TxBytes { get; set; }

    [JsonPropertyName("rx_packets")]
    [JsonConverter(typeof(FlexibleNullableLongConverter))]
    public long? RxPackets { get; set; }

    [JsonPropertyName("tx_packets")]
    [JsonConverter(typeof(FlexibleNullableLongConverter))]
    public long? TxPackets { get; set; }
}

/// <summary>
/// Tolerant nullable-long parser for UniFi API fields that may arrive as a number, a
/// stringified number, or an empty string. Mirrors FlexibleIntConverter but for 64-bit
/// values - DPI byte/packet counters can exceed int range on busy sites.
/// Named distinctly from the non-nullable FlexibleLongConverter in UniFiNetworkConfig.cs.
/// </summary>
public class FlexibleNullableLongConverter : JsonConverter<long?>
{
    public override long? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return reader.TokenType switch
        {
            JsonTokenType.Number when reader.TryGetInt64(out var l) => l,
            JsonTokenType.Number => (long)reader.GetDouble(),
            JsonTokenType.String when long.TryParse(reader.GetString(), out var value) => value,
            JsonTokenType.String => null, // Empty string or non-numeric string
            JsonTokenType.Null => null,
            _ => null
        };
    }

    public override void Write(Utf8JsonWriter writer, long? value, JsonSerializerOptions options)
    {
        if (value.HasValue)
            writer.WriteNumberValue(value.Value);
        else
            writer.WriteNullValue();
    }
}
