using Microsoft.Extensions.Logging;
using NetworkOptimizer.Audit.Models;
using NetworkOptimizer.UniFi.Models;

namespace NetworkOptimizer.Audit.Analyzers;

/// <summary>
/// Analyzes mDNS reflector/repeater scope across networks.
/// UniFi's mDNS service re-broadcasts Bonjour/mDNS advertisements from each network where
/// mdns_enabled is set, so enabling it on an isolated (IoT/Guest) network lets devices on
/// other participating networks discover and reach services there - quietly punching a
/// hole through the isolation the audit otherwise verifies.
///
/// LIMITATION: The UniFi API does not expose which network pairs actually exchange mDNS
/// advertisements (the reflector is global with per-network participation toggles), so a
/// precise "isolated network X shares mDNS with corporate network Y" determination is not
/// possible. This analyzer implements the conservative version: flag mDNS enabled on any
/// network the audit treats as isolated (network_isolation_enabled or UniFi guest purpose).
/// </summary>
public class MdnsScopeAnalyzer
{
    private readonly ILogger<MdnsScopeAnalyzer> _logger;

    public MdnsScopeAnalyzer(ILogger<MdnsScopeAnalyzer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyze network configs for mDNS scope violations.
    /// </summary>
    /// <param name="networkConfigs">Network configurations from /rest/networkconf (null if unavailable)</param>
    /// <returns>List of audit issues found</returns>
    public List<AuditIssue> Analyze(List<UniFiNetworkConfig>? networkConfigs)
    {
        var issues = new List<AuditIssue>();

        if (networkConfigs == null || networkConfigs.Count == 0)
        {
            _logger.LogDebug("No network configs available - skipping mDNS scope analysis");
            return issues;
        }

        foreach (var nc in networkConfigs)
        {
            // Skip dormant/system/WAN-side configs - mDNS only matters on LAN networks
            if (!nc.Enabled || nc.IsSystemNetwork)
                continue;
            if (!string.Equals(nc.Networkgroup, "LAN", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!nc.MdnsEnabled)
                continue;

            var isIsolated = nc.NetworkIsolationEnabled;
            var isGuest = string.Equals(nc.Purpose, "guest", StringComparison.OrdinalIgnoreCase);

            if (!isIsolated && !isGuest)
                continue;

            var isolationBasis = isGuest
                ? "a UniFi guest network (implicit client isolation)"
                : "network isolation enabled";

            issues.Add(new AuditIssue
            {
                Type = IssueTypes.MdnsScope,
                Severity = AuditSeverity.Recommended,
                Message = $"mDNS reflector is enabled on isolated network '{nc.Name}' - service advertisements may be re-broadcast to other networks",
                DeviceName = $"Network: {nc.Name}",
                CurrentNetwork = nc.Name,
                CurrentVlan = nc.Vlan,
                Metadata = new Dictionary<string, object>
                {
                    ["network_id"] = nc.Id,
                    ["network_name"] = nc.Name,
                    ["vlan"] = nc.Vlan ?? 0,
                    ["mdns_enabled"] = nc.MdnsEnabled,
                    ["network_isolation_enabled"] = nc.NetworkIsolationEnabled,
                    ["purpose"] = nc.Purpose
                },
                RuleId = IssueTypes.MdnsScope,
                ScoreImpact = 3,
                RecommendedAction = $"This network has {isolationBasis}, but mDNS is enabled on it. UniFi's mDNS reflector re-broadcasts service advertisements (printers, AirPlay, Chromecast) to other networks where mDNS is enabled, which partially defeats the isolation. If cross-network discovery from this network is not required, disable mDNS for it in UniFi Network > Networks."
            });
        }

        _logger.LogInformation("mDNS scope analysis: {IssueCount} issues", issues.Count);
        return issues;
    }
}
