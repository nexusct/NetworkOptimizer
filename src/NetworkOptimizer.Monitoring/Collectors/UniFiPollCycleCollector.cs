using System.Net;
using Microsoft.Extensions.Logging;
using NetworkOptimizer.Alerts.Events;
using NetworkOptimizer.Core.Enums;
using NetworkOptimizer.Storage.Services;
using NetworkOptimizer.UniFi.Models;

namespace NetworkOptimizer.Monitoring.Collectors;

/// <summary>
/// Single entry point for the UniFi-API-driven poll-cycle enrichment: per-port PoE,
/// AP radio time series, WAN failover detection, and silent-reboot detection over the
/// device list the poll cycle already fetches, plus DHCP pool utilization over
/// networkconf + clients. STP state collection is exposed separately because it
/// needs the per-device SNMP poller and address, which the poll cycle only has
/// inside its SNMP tier.
///
/// Every collector is isolated per device/network: one bad device logs at debug and
/// never breaks the cycle. Alert delivery flows through the shared alert event bus;
/// pass null to collect metrics without alerting.
/// </summary>
public class UniFiPollCycleCollector
{
    private readonly PoeMetricsCollector _poe;
    private readonly ApRadioMetricsCollector _radio;
    private readonly DhcpPoolCollector _dhcp;
    private readonly WanFailoverTracker _wanFailover;
    private readonly StpPortTracker _stp;
    private readonly ILogger<UniFiPollCycleCollector> _logger;

    public UniFiPollCycleCollector(
        MonitoringInfluxClient influx,
        IAlertEventBus? alertEventBus,
        ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger<UniFiPollCycleCollector>();
        _poe = new PoeMetricsCollector(
            influx,
            new PoeBudgetAlertEvaluator(alertEventBus, loggerFactory.CreateLogger<PoeBudgetAlertEvaluator>()),
            loggerFactory.CreateLogger<PoeMetricsCollector>());
        _radio = new ApRadioMetricsCollector(influx, loggerFactory.CreateLogger<ApRadioMetricsCollector>());
        _dhcp = new DhcpPoolCollector(influx, loggerFactory.CreateLogger<DhcpPoolCollector>());
        _wanFailover = new WanFailoverTracker(influx, alertEventBus, loggerFactory.CreateLogger<WanFailoverTracker>());
        _stp = new StpPortTracker(influx, loggerFactory.CreateLogger<StpPortTracker>());
    }

    /// <summary>
    /// Runs all device-JSON collectors for one poll cycle: PoE (+ budget alerting),
    /// AP radio series, and WAN failover detection.
    /// </summary>
    public async Task CollectDeviceMetricsAsync(
        IReadOnlyList<UniFiDeviceResponse> devices,
        DateTime? timestamp = null,
        CancellationToken ct = default)
    {
        var ts = timestamp ?? DateTime.UtcNow;

        foreach (var device in devices)
        {
            var deviceType = DescribeDeviceType(device.DeviceType);

            await RunIsolated("poe", device.Mac,
                () => _poe.CollectAsync(device, deviceType, ts, ct), ct);
            await RunIsolated("ap_radio", device.Mac,
                () => _radio.CollectAsync(device, ts, ct), ct);
            await RunIsolated("wan_failover", device.Mac,
                () => _wanFailover.TrackAsync(device, ts, ct), ct);
        }
    }

    /// <summary>
    /// Computes DHCP pool utilization per network from networkconf ranges and the
    /// current client list.
    /// </summary>
    public Task CollectDhcpPoolsAsync(
        IReadOnlyList<UniFiNetworkConfig> networks,
        IReadOnlyList<UniFiClientResponse> clients,
        DateTime? timestamp = null,
        CancellationToken ct = default) =>
        _dhcp.CollectAsync(networks, clients, timestamp ?? DateTime.UtcNow, ct);

    /// <summary>
    /// Collects STP port states for one device via its SNMP poller. Call from the
    /// SNMP tier of the poll cycle, where the per-device poller/address exist.
    /// </summary>
    public Task CollectStpPortStatesAsync(
        SnmpPoller poller,
        IPAddress ip,
        UniFiDeviceResponse device,
        DateTime? timestamp = null,
        CancellationToken ct = default) =>
        _stp.CollectAsync(poller, ip, device.Mac, device.Name, device.PortTable,
            timestamp ?? DateTime.UtcNow, ct);

    /// <summary>
    /// One collector failing on one device must not break the poll cycle - log at
    /// debug (consistent with SnmpPoller's failure handling) and move on.
    /// </summary>
    private async Task RunIsolated(string collector, string deviceMac, Func<Task> run, CancellationToken ct)
    {
        try
        {
            await run();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "{Collector} collection failed for {DeviceMac}", collector, deviceMac);
        }
    }

    // Same lowercase labels the poll cycle writes on device_health points.
    private static string DescribeDeviceType(DeviceType type) => type switch
    {
        DeviceType.Gateway => "gateway",
        DeviceType.Switch => "switch",
        DeviceType.AccessPoint => "ap",
        _ => "unknown"
    };
}
