using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetworkOptimizer.Storage.Services;
using NetworkOptimizer.UniFi.Models;

namespace NetworkOptimizer.Monitoring.Collectors;

/// <summary>
/// Computes per-network DHCP pool utilization and writes it to the dhcp_pool
/// measurement. Pool size comes from the networkconf DHCP range (dhcpd_start/stop);
/// active leases are the clients currently on that network with an IP inside the
/// pool range (client network_id match, falling back to the network name for older
/// firmware that omits the id).
///
/// Networks without DHCP enabled, without a valid IPv4 range, or with an inverted
/// range are skipped silently - partial controller data must not break the cycle.
/// </summary>
public class DhcpPoolCollector
{
    private readonly MonitoringInfluxClient _influx;
    private readonly ILogger<DhcpPoolCollector> _logger;

    public DhcpPoolCollector(MonitoringInfluxClient influx, ILogger<DhcpPoolCollector> logger)
    {
        _influx = influx;
        _logger = logger;
    }

    public async Task CollectAsync(
        IReadOnlyList<UniFiNetworkConfig> networks,
        IReadOnlyList<UniFiClientResponse> clients,
        DateTime timestamp,
        CancellationToken ct = default)
    {
        foreach (var network in networks)
        {
            if (!network.DhcpdEnabled)
                continue;
            if (!TryParseRange(network.DhcpdStart, network.DhcpdStop, out var startV, out var stopV))
                continue;

            var poolSize = (long)(stopV - startV) + 1;
            if (poolSize <= 0)
                continue;

            long activeLeases = 0;
            foreach (var client in clients)
            {
                if (!ClientBelongsToNetwork(client, network))
                    continue;
                if (!IPAddress.TryParse(client.Ip, out var ip) ||
                    ip.AddressFamily != AddressFamily.InterNetwork)
                    continue;
                var v = IpToUInt32(ip);
                if (v >= startV && v <= stopV)
                    activeLeases++;
            }

            var utilization = activeLeases * 100.0 / poolSize;

            await _influx.WriteDhcpPoolAsync(
                network.Id, network.Name, network.Vlan, network.IpSubnet,
                network.DhcpdStart!, network.DhcpdStop!,
                poolSize, activeLeases, utilization, timestamp);
        }
    }

    private static bool ClientBelongsToNetwork(UniFiClientResponse client, UniFiNetworkConfig network)
    {
        if (!string.IsNullOrEmpty(client.NetworkId) && !string.IsNullOrEmpty(network.Id))
            return string.Equals(client.NetworkId, network.Id, StringComparison.Ordinal);
        return !string.IsNullOrEmpty(client.Network) &&
               string.Equals(client.Network, network.Name, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Validates and converts an IPv4 start/stop pair to sortable uints.</summary>
    private static bool TryParseRange(string? start, string? stop, out uint startV, out uint stopV)
    {
        startV = stopV = 0;
        if (!IPAddress.TryParse(start, out var startIp) || !IPAddress.TryParse(stop, out var stopIp))
            return false;
        if (startIp.AddressFamily != AddressFamily.InterNetwork ||
            stopIp.AddressFamily != AddressFamily.InterNetwork)
            return false;
        startV = IpToUInt32(startIp);
        stopV = IpToUInt32(stopIp);
        return stopV >= startV;
    }

    private static uint IpToUInt32(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }
}
