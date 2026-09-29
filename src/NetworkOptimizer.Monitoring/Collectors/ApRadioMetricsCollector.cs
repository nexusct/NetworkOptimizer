using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetworkOptimizer.Storage.Services;
using NetworkOptimizer.UniFi.Models;

namespace NetworkOptimizer.Monitoring.Collectors;

/// <summary>
/// Writes per-radio AP time series (channel, width, utilization, interference,
/// TX retries, client count) to the ap_radio measurement. Runtime values come from
/// radio_table_stats (what the radio is actually doing); radio_table config fills in
/// width/channel only when stats lack them (e.g. a mesh backhaul radio negotiating
/// down from its configured width is reported at the negotiated width).
///
/// Non-AP devices (no radio_table_stats) produce no writes.
/// </summary>
public class ApRadioMetricsCollector
{
    private readonly MonitoringInfluxClient _influx;
    private readonly ILogger<ApRadioMetricsCollector> _logger;

    public ApRadioMetricsCollector(MonitoringInfluxClient influx, ILogger<ApRadioMetricsCollector> logger)
    {
        _influx = influx;
        _logger = logger;
    }

    public async Task CollectAsync(UniFiDeviceResponse device, DateTime timestamp, CancellationToken ct = default)
    {
        if (device.RadioTableStats == null || device.RadioTableStats.Count == 0 ||
            string.IsNullOrEmpty(device.Mac))
            return;

        var configByName = new Dictionary<string, RadioTableEntry>(StringComparer.OrdinalIgnoreCase);
        if (device.RadioTable != null)
        {
            foreach (var entry in device.RadioTable)
            {
                if (!string.IsNullOrEmpty(entry.Name))
                    configByName[entry.Name] = entry;
            }
        }

        foreach (var stats in device.RadioTableStats)
        {
            var band = MapBand(stats.Radio);
            if (string.IsNullOrEmpty(band) || string.IsNullOrEmpty(stats.Name))
                continue;

            configByName.TryGetValue(stats.Name, out var config);

            // Stats channel/width reflect the radio as-running; config ("auto" or a
            // fixed value) is the fallback when stats omit them.
            var channel = stats.Channel ?? ParseConfigChannel(config?.Channel);
            var width = stats.Bw ?? config?.ChannelWidth;

            await _influx.WriteApRadioAsync(
                device.Mac, stats.Name, band,
                channel, width,
                stats.CuTotal, stats.CuSelfRx, stats.CuSelfTx,
                stats.Interference, stats.TxRetriesPct, stats.TxPower,
                stats.Satisfaction, stats.NumSta,
                timestamp);
        }
    }

    /// <summary>
    /// UniFi band codes to the lowercase band labels used by the wifi_client
    /// measurement ("2.4ghz"/"5ghz"/"6ghz"). Unknown codes yield no point.
    /// </summary>
    internal static string MapBand(string? radio) => radio switch
    {
        "ng" => "2.4ghz",
        "na" => "5ghz",
        "6e" => "6ghz",
        "6g" => "6ghz",
        _ => string.Empty
    };

    /// <summary>
    /// radio_table.channel is typed as object because UniFi sends either a number or
    /// the string "auto". Returns null for "auto"/unparseable values.
    /// </summary>
    internal static int? ParseConfigChannel(object? channel) => channel switch
    {
        null => null,
        JsonElement { ValueKind: JsonValueKind.Number } el when el.TryGetInt32(out var n) => n,
        JsonElement { ValueKind: JsonValueKind.String } el => ParseChannelString(el.GetString()),
        int n => n,
        string s => ParseChannelString(s),
        _ => null
    };

    private static int? ParseChannelString(string? s) =>
        int.TryParse(s, out var n) ? n : null;
}
