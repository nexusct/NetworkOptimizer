using Microsoft.Extensions.Logging;
using NetworkOptimizer.Audit.Models;
using NetworkOptimizer.Audit.Scoring;
using NetworkOptimizer.UniFi.Models;

namespace NetworkOptimizer.Audit.Analyzers;

/// <summary>
/// Analyzes WLAN (SSID) configurations from /rest/wlanconf for wireless security issues:
/// open/WEP networks, legacy WPA1/TKIP security, disabled protected management frames (802.11w),
/// and guest networks without client (L2) isolation.
/// </summary>
public class WirelessConfigAnalyzer
{
    private readonly ILogger<WirelessConfigAnalyzer> _logger;

    public WirelessConfigAnalyzer(ILogger<WirelessConfigAnalyzer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyze WLAN configurations for wireless security issues.
    /// </summary>
    /// <param name="wlanConfigs">WLAN configurations from /rest/wlanconf (null if unavailable)</param>
    /// <param name="networks">Extracted networks (for guest network resolution)</param>
    /// <param name="networkConfigs">Raw network configs from /rest/networkconf (for guest purpose resolution)</param>
    /// <returns>List of audit issues found</returns>
    public List<AuditIssue> Analyze(
        List<UniFiWlanConfig>? wlanConfigs,
        List<NetworkInfo> networks,
        List<UniFiNetworkConfig>? networkConfigs)
    {
        var issues = new List<AuditIssue>();

        if (wlanConfigs == null || wlanConfigs.Count == 0)
        {
            _logger.LogDebug("No WLAN configurations available - skipping wireless config analysis");
            return issues;
        }

        // Guest-purpose network IDs from raw network configs (purpose == "guest")
        var guestNetworkIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (networkConfigs != null)
        {
            foreach (var nc in networkConfigs)
            {
                if (!string.IsNullOrEmpty(nc.Id) &&
                    string.Equals(nc.Purpose, "guest", StringComparison.OrdinalIgnoreCase))
                {
                    guestNetworkIds.Add(nc.Id);
                }
            }
        }

        // Also consider networks classified as Guest by the audit engine
        foreach (var n in networks)
        {
            if (n.Purpose == NetworkPurpose.Guest || n.IsUniFiGuestNetwork)
                guestNetworkIds.Add(n.Id);
        }

        foreach (var wlan in wlanConfigs)
        {
            // Disabled WLANs are dormant config - skip them
            if (!wlan.Enabled)
                continue;

            var ssid = string.IsNullOrWhiteSpace(wlan.Name) ? "(unnamed SSID)" : wlan.Name;
            var security = wlan.Security?.Trim().ToLowerInvariant();

            var openIssue = CheckOpenOrWep(wlan, ssid, security);
            if (openIssue != null)
                issues.Add(openIssue);

            var legacyIssue = CheckLegacySecurity(wlan, ssid, security);
            if (legacyIssue != null)
                issues.Add(legacyIssue);

            var pmfIssue = CheckPmfDisabled(wlan, ssid, security);
            if (pmfIssue != null)
                issues.Add(pmfIssue);

            var guestIssue = CheckGuestIsolation(wlan, ssid, guestNetworkIds);
            if (guestIssue != null)
                issues.Add(guestIssue);
        }

        _logger.LogInformation("Wireless config analysis: {IssueCount} issues across {WlanCount} enabled WLANs",
            issues.Count, wlanConfigs.Count(w => w.Enabled));

        return issues;
    }

    /// <summary>
    /// WLAN-OPEN-SSID (Critical): WLAN with no/open security or legacy WEP.
    /// </summary>
    private AuditIssue? CheckOpenOrWep(UniFiWlanConfig wlan, string ssid, string? security)
    {
        var isOpen = string.IsNullOrEmpty(security) || security == "open";
        var isWep = security == "wep";

        if (!isOpen && !isWep)
            return null;

        var message = isWep
            ? $"WLAN '{ssid}' uses legacy WEP security - trivially crackable"
            : $"WLAN '{ssid}' has no password (open network)";

        var recommendation = isWep
            ? "WEP encryption was broken in 2001 and can be cracked in minutes. Change this WLAN's security to WPA2-AES or WPA3 in UniFi Network > WiFi settings."
            : "Anyone in radio range can join this network and sniff all traffic. Set a strong WPA2-AES or WPA3 password in UniFi Network > WiFi settings. If this is an intentional guest portal network, ensure it is on a Guest network with client isolation enabled.";

        return new AuditIssue
        {
            Type = IssueTypes.WlanOpenSsid,
            Severity = AuditSeverity.Critical,
            Message = message,
            DeviceName = $"SSID: {ssid}",
            Metadata = new Dictionary<string, object>
            {
                ["ssid"] = ssid,
                ["security"] = security ?? "open",
                ["wlan_id"] = wlan.Id
            },
            RuleId = IssueTypes.WlanOpenSsid,
            ScoreImpact = ScoreConstants.CriticalImpact,
            RecommendedAction = recommendation
        };
    }

    /// <summary>
    /// WLAN-LEGACY-SECURITY (Critical): WPA1 or TKIP in use (mixed-mode WPA/WPA2-TKIP counts).
    /// </summary>
    private AuditIssue? CheckLegacySecurity(UniFiWlanConfig wlan, string ssid, string? security)
    {
        if (string.IsNullOrEmpty(security))
            return null; // Handled by open-SSID check

        // UniFi wlanconf security values:
        //   "wpapsk"      = WPA1-Personal only
        //   "wpawpa2psk"  = WPA/WPA2 mixed mode (WPA1 with TKIP enabled)
        //   "wpa"/"wpawpa2" = WPA1 / mixed enterprise variants
        // TKIP may also appear as an explicit substring on some firmware versions.
        var isWpa1Only = security is "wpapsk" or "wpa";
        var isMixedWpa1 = security is "wpawpa2psk" or "wpawpa2" or "wpa-wpa2";
        var usesTkip = security.Contains("tkip");

        if (!isWpa1Only && !isMixedWpa1 && !usesTkip)
            return null;

        // Note: WPA2-only networks using TKIP (wpa_enc=tkip) cannot be detected here -
        // UniFiWlanConfig does not model the wpa_enc field, so that variant is missed.
        var modeLabel = isWpa1Only
            ? "WPA1-only"
            : isMixedWpa1 ? "WPA/WPA2 mixed mode (WPA1 with TKIP enabled)" : "TKIP encryption";

        return new AuditIssue
        {
            Type = IssueTypes.WlanLegacySecurity,
            Severity = AuditSeverity.Critical,
            Message = $"WLAN '{ssid}' uses legacy security: {modeLabel}",
            DeviceName = $"SSID: {ssid}",
            Metadata = new Dictionary<string, object>
            {
                ["ssid"] = ssid,
                ["security"] = security,
                ["wlan_id"] = wlan.Id
            },
            RuleId = IssueTypes.WlanLegacySecurity,
            ScoreImpact = 10,
            RecommendedAction = "WPA1 and TKIP have known cryptographic weaknesses (TKIP attacks, KRACK-adjacent downgrade paths). Change this WLAN to WPA2-AES only or WPA3 in UniFi Network > WiFi settings. Mixed mode exists only for ancient clients - replace or retire any device that cannot do WPA2-AES."
        };
    }

    /// <summary>
    /// WLAN-PMF-DISABLED (Recommended): protected management frames (802.11w) disabled.
    /// LIMITATION: UniFiWlanConfig does not model the pmf_mode field, so PMF state cannot
    /// be observed from the typed API model. WPA3 WLANs are known-safe (PMF is mandatory
    /// in WPA3) and are skipped; for all other security modes the check stays silent rather
    /// than guessing. Adding pmf_mode to the UniFi model would activate precise detection.
    /// </summary>
    private AuditIssue? CheckPmfDisabled(UniFiWlanConfig wlan, string ssid, string? security)
    {
        // WPA3 (including WPA2/WPA3 transition) requires PMF to be at least optional -
        // these are never vulnerable to deauth via unprotected management frames.
        if (security?.Contains("wpa3") == true)
            return null;

        // For WPA2-only and open WLANs, PMF state is not exposed by UniFiWlanConfig.
        // Skip silently rather than speculate (older firmware also omits the field).
        _logger.LogDebug("WLAN '{Ssid}': PMF (802.11w) state not exposed by UniFiWlanConfig model - skipping PMF check", ssid);

        return null;
    }

    /// <summary>
    /// WLAN-GUEST-NO-ISOLATION (Critical): SSID mapped to a guest/hotspot-purpose network
    /// without L2/client isolation enabled.
    /// </summary>
    private AuditIssue? CheckGuestIsolation(UniFiWlanConfig wlan, string ssid, HashSet<string> guestNetworkIds)
    {
        var isGuestWlan = wlan.IsGuest ||
            (!string.IsNullOrEmpty(wlan.NetworkConfId) && guestNetworkIds.Contains(wlan.NetworkConfId));

        if (!isGuestWlan)
            return null;

        if (wlan.L2Isolation)
            return null; // Correctly configured

        return new AuditIssue
        {
            Type = IssueTypes.WlanGuestNoIsolation,
            Severity = AuditSeverity.Critical,
            Message = $"Guest WLAN '{ssid}' does not have client (L2) isolation enabled - guest devices can reach each other",
            DeviceName = $"SSID: {ssid}",
            Metadata = new Dictionary<string, object>
            {
                ["ssid"] = ssid,
                ["is_guest"] = wlan.IsGuest,
                ["networkconf_id"] = wlan.NetworkConfId ?? "",
                ["l2_isolation"] = wlan.L2Isolation,
                ["wlan_id"] = wlan.Id
            },
            RuleId = IssueTypes.WlanGuestNoIsolation,
            ScoreImpact = 10,
            RecommendedAction = "Enable 'Client Device Isolation' (L2 isolation) on this WLAN in UniFi Network > WiFi settings. Without it, any guest device can attack or snoop on every other guest device on the same SSID."
        };
    }
}
