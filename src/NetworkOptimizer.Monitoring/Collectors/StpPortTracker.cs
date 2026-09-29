using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using NetworkOptimizer.Monitoring.Models;
using NetworkOptimizer.Storage.Services;
using NetworkOptimizer.UniFi;
using NetworkOptimizer.UniFi.Models;

namespace NetworkOptimizer.Monitoring.Collectors;

/// <summary>
/// Collects per-port spanning-tree state (SNMP Bridge MIB via
/// <see cref="SnmpPoller.GetStpPortStatesAsync"/>) into the stp_port measurement and
/// writes an event when a port transitions from blocking to forwarding - on a
/// stable switched network that transition usually means a topology change (new
/// loop, new switch, failed uplink) worth reviewing.
///
/// Interfaces are correlated back to UniFi front-panel ports through
/// InterfacePortCorrelation (switch port_table entries usually lack ifname but keep
/// PortIdx == ifIndex). Ports that can't be correlated are still recorded under
/// their SNMP ifName. Devices without Bridge MIB data produce no writes and no
/// state changes, so absence of STP support never masquerades as a transition.
/// </summary>
public class StpPortTracker
{
    private readonly MonitoringInfluxClient _influx;
    private readonly ILogger<StpPortTracker> _logger;

    // Last observed state per device+ifIndex ("mac:ifindex").
    private readonly ConcurrentDictionary<string, StpPortState> _lastStateByPort = new();

    public StpPortTracker(MonitoringInfluxClient influx, ILogger<StpPortTracker> logger)
    {
        _influx = influx;
        _logger = logger;
    }

    public async Task CollectAsync(
        SnmpPoller poller,
        IPAddress ip,
        string deviceMac,
        string? deviceName,
        IReadOnlyList<SwitchPort>? portTable,
        DateTime timestamp,
        CancellationToken ct = default)
    {
        var states = await poller.GetStpPortStatesAsync(ip, deviceName);
        if (states.Count == 0)
            return;

        var macKey = deviceMac.ToLowerInvariant();

        foreach (var port in states)
        {
            var correlation = InterfacePortCorrelation.Correlate(
                portTable, port.IfIndex, snmpSpeedBps: 0, rawIfName: port.IfName, monitoredIfName: port.IfName);
            int? portIdx = correlation.PortNumber;

            // Prefer the SNMP ifName; fall back to the correlated port number, then
            // the raw ifIndex, so every recorded port has a stable label.
            var ifName = !string.IsNullOrEmpty(port.IfName)
                ? port.IfName
                : portIdx.HasValue ? $"port{portIdx.Value}" : $"if{port.IfIndex}";

            await _influx.WriteStpPortAsync(
                deviceMac, ifName, portIdx, port.State.ToName(), (int)port.State, timestamp);

            var key = $"{macKey}:{port.IfIndex}";
            if (_lastStateByPort.TryGetValue(key, out var previous) &&
                previous == StpPortState.Blocking && port.State == StpPortState.Forwarding)
            {
                var label = string.IsNullOrEmpty(deviceName) ? deviceMac : deviceName;
                _logger.LogInformation("STP topology change on {Device}: port {Port} blocking -> forwarding",
                    label, ifName);

                await _influx.WriteEventAsync(
                    deviceMac, "stp_port_forwarding", "warning",
                    $"Port {ifName} transitioned from blocking to forwarding (topology change)",
                    ifName, previous.ToName(), port.State.ToName(), timestamp);
            }

            _lastStateByPort[key] = port.State;
        }
    }
}
