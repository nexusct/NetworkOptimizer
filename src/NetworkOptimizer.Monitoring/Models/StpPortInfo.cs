namespace NetworkOptimizer.Monitoring.Models;

/// <summary>
/// Spanning-tree port state per the Bridge MIB dot1dStpPortState (RFC 4188).
/// Numeric values match the SNMP encoding exactly.
/// </summary>
public enum StpPortState
{
    Unknown = 0,
    Disabled = 1,
    Blocking = 2,
    Listening = 3,
    Learning = 4,
    Forwarding = 5,
    Broken = 6
}

/// <summary>One port's spanning-tree state from a Bridge MIB poll.</summary>
public sealed record StpPortInfo(int IfIndex, string? IfName, StpPortState State);

public static class StpPortStateExtensions
{
    public static StpPortState FromCode(int code) => code switch
    {
        1 => StpPortState.Disabled,
        2 => StpPortState.Blocking,
        3 => StpPortState.Listening,
        4 => StpPortState.Learning,
        5 => StpPortState.Forwarding,
        6 => StpPortState.Broken,
        _ => StpPortState.Unknown
    };

    /// <summary>Lowercase state name used for the stp_port measurement and event values.</summary>
    public static string ToName(this StpPortState state) => state switch
    {
        StpPortState.Disabled => "disabled",
        StpPortState.Blocking => "blocking",
        StpPortState.Listening => "listening",
        StpPortState.Learning => "learning",
        StpPortState.Forwarding => "forwarding",
        StpPortState.Broken => "broken",
        _ => "unknown"
    };
}
