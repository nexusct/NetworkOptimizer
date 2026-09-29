using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkOptimizer.Alerts.Events;
using NetworkOptimizer.Core.Enums;
using NetworkOptimizer.Storage.Services;
using NetworkOptimizer.UniFi;
using NetworkOptimizer.UniFi.Models;

namespace NetworkOptimizer.Monitoring.Collectors;

/// <summary>
/// Tracks each gateway's active WAN across poll cycles and emits an event plus an
/// alert when it changes (failover or failback). Active WAN resolution reuses
/// UniFiDiscovery.ResolveActiveWanInterface so the tracked interface is exactly the
/// one the rest of the monitoring subsystem measures.
///
/// The first observation per gateway only establishes a baseline - no event. Polls
/// where the active WAN can't be resolved leave the baseline untouched rather than
/// flapping state on transient controller data gaps.
/// </summary>
public class WanFailoverTracker
{
    private readonly MonitoringInfluxClient _influx;
    private readonly IAlertEventBus? _eventBus;
    private readonly ILogger<WanFailoverTracker> _logger;

    // Normalized WAN interface key per gateway MAC ("wan", "wan2", ...).
    private readonly ConcurrentDictionary<string, string> _activeWanByMac = new();

    public WanFailoverTracker(
        MonitoringInfluxClient influx,
        IAlertEventBus? eventBus,
        ILogger<WanFailoverTracker> logger)
    {
        _influx = influx;
        _eventBus = eventBus;
        _logger = logger;
    }

    public async Task TrackAsync(UniFiDeviceResponse device, DateTime timestamp, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(device.Mac))
            return;

        var wans = device.GetWanInterfaces();
        if (wans.Count == 0)
            return; // not a gateway, or the controller didn't report WAN objects

        var (physicalIfName, uplinkIfName) = UniFiDiscovery.ResolveActiveWanInterface(device);

        var active = wans.FirstOrDefault(w =>
            (!string.IsNullOrEmpty(physicalIfName) &&
             string.Equals(w.IfName, physicalIfName, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(uplinkIfName) &&
             string.Equals(w.UplinkIfName, uplinkIfName, StringComparison.OrdinalIgnoreCase)));

        if (active == null || string.IsNullOrEmpty(active.Key))
        {
            // Resolved an interface but no wan object claims it (shouldn't happen when
            // ResolveActiveWanInterface matched from the wan list), or nothing resolved.
            // Leave the baseline alone rather than flap on incomplete data.
            return;
        }

        // Normalize so "wan" and "wan1" (both WAN1) compare equal.
        var activeKey = GatewayWanHelper.WanInterfaceKeyFromKey(active.Key);
        var mac = device.Mac.ToLowerInvariant();

        if (!_activeWanByMac.TryGetValue(mac, out var previousKey))
        {
            _activeWanByMac[mac] = activeKey;
            return; // baseline only
        }

        if (string.Equals(previousKey, activeKey, StringComparison.OrdinalIgnoreCase))
            return;

        _activeWanByMac[mac] = activeKey;

        var label = string.IsNullOrEmpty(device.Name) ? device.Mac : device.Name;
        var detail = $"Active WAN changed from {previousKey} to {activeKey}";

        _logger.LogInformation("WAN failover on {Device}: {Detail}", label, detail);

        await _influx.WriteEventAsync(
            device.Mac, "wan_failover", "warning", detail,
            ifName: physicalIfName, oldValue: previousKey, newValue: activeKey, timestamp);

        if (_eventBus != null)
        {
            await _eventBus.PublishAsync(new AlertEvent
            {
                EventType = "wan.failover",
                Source = "wan",
                Severity = AlertSeverity.Warning,
                Title = $"{label} WAN failover",
                Message = $"Gateway {label} switched its active WAN from {previousKey} to {activeKey}.",
                DeviceId = device.Mac,
                DeviceName = device.Name,
                SourceUrl = "/monitoring?tab=devices",
                Tags = ["device", "gateway", "wan", "failover"],
                Context = new Dictionary<string, string>
                {
                    ["device_mac"] = device.Mac,
                    ["old_wan"] = previousKey,
                    ["new_wan"] = activeKey
                }
            }, ct);
        }
    }
}
