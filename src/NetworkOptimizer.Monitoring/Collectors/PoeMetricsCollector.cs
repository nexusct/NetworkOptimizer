using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetworkOptimizer.Storage.Services;
using NetworkOptimizer.UniFi.Models;

namespace NetworkOptimizer.Monitoring.Collectors;

/// <summary>
/// Extracts per-port PoE telemetry from a UniFi API device response (port_table)
/// and writes it to InfluxDB. Per-port points land on the poe_port measurement;
/// per-device totals and budget utilization piggyback on device_health via the
/// custom-fields write path (same tag set as WriteDeviceHealthAsync), mirroring how
/// custom-OID values attach to existing measurements.
///
/// Devices without PoE ports produce no writes. Unparseable power values are treated
/// as absent, never as errors - a device mid-reboot or on older firmware must not
/// break the poll cycle.
/// </summary>
public class PoeMetricsCollector
{
    private readonly MonitoringInfluxClient _influx;
    private readonly PoeBudgetAlertEvaluator _budgetAlerts;
    private readonly ILogger<PoeMetricsCollector> _logger;

    public PoeMetricsCollector(
        MonitoringInfluxClient influx,
        PoeBudgetAlertEvaluator budgetAlerts,
        ILogger<PoeMetricsCollector> logger)
    {
        _influx = influx;
        _budgetAlerts = budgetAlerts;
        _logger = logger;
    }

    /// <summary>
    /// Collect PoE telemetry for one device. <paramref name="deviceType"/> must be the
    /// same lowercase string used by WriteDeviceHealthAsync ("gateway"/"switch"/"ap")
    /// so the piggybacked device-level fields land on the same device_health series.
    /// </summary>
    public async Task CollectAsync(
        UniFiDeviceResponse device, string? deviceType, DateTime timestamp, CancellationToken ct = default)
    {
        if (device.PortTable == null || string.IsNullOrEmpty(device.Mac))
            return;

        double totalW = 0;
        var poeCapable = 0;
        var activePorts = 0;

        foreach (var port in device.PortTable)
        {
            if (!port.PortPoe)
                continue;

            poeCapable++;
            // UniFi reports poe_power/poe_voltage as strings (e.g. "3.42"); absent
            // when the port delivers no power.
            var powerW = ParseMeasurement(port.PoePower);
            var voltageV = ParseMeasurement(port.PoeVoltage);

            if (powerW is > 0)
            {
                totalW += powerW.Value;
                activePorts++;
            }

            await _influx.WritePoePortAsync(
                device.Mac, port.PortIdx, port.Name, port.PoeMode, port.PoeEnable,
                powerW, voltageV, timestamp);
        }

        if (poeCapable == 0)
            return;

        var budgetW = ReadBudgetWatts(device);
        double? budgetPct = budgetW is > 0 ? totalW / budgetW.Value * 100.0 : null;

        // Device-level summary piggybacks on device_health (custom-OID pattern): the
        // tag set (device_mac + device_type) matches WriteDeviceHealthAsync exactly.
        var fields = new Dictionary<string, object>
        {
            ["poe_total_w"] = totalW,
            ["poe_ports_active"] = (long)activePorts,
            ["poe_ports_capable"] = (long)poeCapable
        };
        if (budgetW is > 0)
        {
            fields["poe_budget_w"] = budgetW.Value;
            fields["poe_budget_pct"] = budgetPct!.Value;
        }

        await _influx.WriteCustomFieldsAsync(
            "device_health", device.Mac, fields, deviceType, ifName: null, portId: null, timestamp);

        if (budgetPct.HasValue)
        {
            await _budgetAlerts.EvaluateAsync(
                device.Mac, device.Name, budgetPct.Value, totalW, budgetW!.Value, ct);
        }
    }

    /// <summary>
    /// Parses a UniFi string-typed measurement ("3.42") to a double. Returns null for
    /// absent or malformed values - never throws.
    /// </summary>
    internal static double? ParseMeasurement(string? raw) =>
        double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;

    /// <summary>
    /// Reads the device's PoE power budget in watts from unmapped extension data.
    /// UniFi exposes it under different top-level keys depending on firmware
    /// ("poe_power_budget" on current firmware, "total_max_power" on older); neither
    /// is mapped to a typed property on UniFiDeviceResponse. Returns null when the
    /// device reports no budget (non-PoE devices, unknown firmware) - callers treat
    /// that as "no budget tracking", not an error.
    /// </summary>
    private static double? ReadBudgetWatts(UniFiDeviceResponse device)
    {
        if (device.AdditionalData == null)
            return null;

        foreach (var key in new[] { "poe_power_budget", "total_max_power" })
        {
            if (device.AdditionalData.TryGetValue(key, out var el) &&
                el.ValueKind == JsonValueKind.Number &&
                el.TryGetDouble(out var watts) && watts > 0)
            {
                return watts;
            }
        }

        return null;
    }
}
