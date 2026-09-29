using NetworkOptimizer.Audit.Models;

namespace NetworkOptimizer.Audit.Rules;

/// <summary>
/// Checks that access ports have storm control enabled via their assigned port profile.
/// Storm control rate-limits broadcast, multicast, and unknown-unicast floods, which
/// protects the switch and connected clients from broadcast storms and simple DoS loops.
/// </summary>
public class StormControlRule : AuditRuleBase
{
    public override string RuleId => "STORM-CONTROL-001";
    public override string RuleName => "Storm Control on Access Ports";
    public override string Description => "Access ports should have storm control (broadcast/multicast/unknown-unicast) enabled via their port profile";
    public override AuditSeverity Severity => AuditSeverity.Recommended;
    public override int ScoreImpact => 2;

    public override AuditIssue? Evaluate(PortInfo port, List<NetworkInfo> networks, List<NetworkInfo>? allNetworks = null)
    {
        // Only check access ports (native forward mode) - trunk/uplink ports legitimately
        // carry high broadcast/multicast volume and must not be rate-limited blindly
        if (port.ForwardMode != "native" || port.IsUplink || port.IsWan)
            return null;

        // Skip mirror destination ports (consistent with other access-port rules)
        if (port.IsMirrorDestination)
            return null;

        // Storm control is configured on the port profile - if the port has no resolvable
        // profile, we cannot determine its storm control state, so skip silently
        var profile = port.AssignedPortProfile;
        if (profile == null)
            return null;

        // Any one of the three storm control types enabled counts as configured
        if (profile.StormCtrlBcastEnabled || profile.StormCtrlMcastEnabled || profile.StormCtrlUcastEnabled)
            return null;

        return CreateIssue(
            $"Access port profile '{profile.Name}' has storm control disabled on all types (broadcast, multicast, unknown-unicast)",
            port,
            new Dictionary<string, object>
            {
                { "profile_name", profile.Name },
                { "profile_id", profile.Id },
                { "stormctrl_bcast_enabled", profile.StormCtrlBcastEnabled },
                { "stormctrl_mcast_enabled", profile.StormCtrlMcastEnabled },
                { "stormctrl_ucast_enabled", profile.StormCtrlUcastEnabled }
            },
            "Enable storm control (at minimum broadcast, optionally multicast and unknown-unicast) on this port profile in UniFi Network > Port Profiles. " +
            "Storm control rate-limits flood traffic so a single malfunctioning or malicious device cannot storm the whole network.");
    }
}
