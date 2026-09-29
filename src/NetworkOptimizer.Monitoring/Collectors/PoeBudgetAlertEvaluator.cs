using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkOptimizer.Alerts.Events;
using NetworkOptimizer.Core.Enums;

namespace NetworkOptimizer.Monitoring.Collectors;

/// <summary>
/// Evaluates per-device PoE budget utilization and publishes alert events on breach.
/// Follows the DeviceHealthAlertEvaluator pattern: hysteresis around the threshold
/// (clear margin) plus a minimum consecutive-sample count so a single spiky poll
/// doesn't alert, and one alert per breach episode (escalation from warning to
/// critical publishes a fresh event); repeat suppression lives in the alert rule's
/// cooldown, as with the other monitoring alerts.
///
/// Only fires when the device reports a PoE budget - devices without one never
/// reach this evaluator (see PoeMetricsCollector).
/// </summary>
public class PoeBudgetAlertEvaluator
{
    /// <summary>Warn when PoE draw exceeds this share of the device budget.</summary>
    public const double WarnThresholdPercent = 80.0;

    /// <summary>Critical when PoE draw exceeds this share of the device budget.</summary>
    public const double CriticalThresholdPercent = 95.0;

    // Draw must fall this far below the warn threshold before the alert re-arms,
    // preventing flapping for devices hovering near the limit.
    private const double ClearMarginPercent = 5.0;

    // Utilization must breach on this many consecutive polls before alerting
    // (duration equivalent; at typical poll intervals ~2-3 minutes).
    private const int MinBreachingSamples = 3;

    private readonly IAlertEventBus? _eventBus;
    private readonly ILogger<PoeBudgetAlertEvaluator> _logger;
    private readonly ConcurrentDictionary<string, PoeBudgetState> _states = new();

    public PoeBudgetAlertEvaluator(IAlertEventBus? eventBus, ILogger<PoeBudgetAlertEvaluator> logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public async ValueTask EvaluateAsync(
        string deviceMac, string? deviceName, double budgetPct, double totalW, double budgetW,
        CancellationToken ct = default)
    {
        var state = _states.GetOrAdd(deviceMac, _ => new PoeBudgetState());

        var severity =
            budgetPct >= CriticalThresholdPercent ? AlertSeverity.Critical :
            budgetPct >= WarnThresholdPercent ? AlertSeverity.Warning :
            (AlertSeverity?)null;

        if (severity == null)
        {
            // Below warn threshold: re-arm only once comfortably clear, so a device
            // oscillating around 80% doesn't re-alert every episode boundary.
            if (state.BreachedSeverity != null && budgetPct <= WarnThresholdPercent - ClearMarginPercent)
                state.BreachedSeverity = null;
            state.ConsecutiveBreaches = 0;
            return;
        }

        state.ConsecutiveBreaches++;
        if (state.ConsecutiveBreaches < MinBreachingSamples)
            return;

        // One event per breach episode; an escalation (warning -> critical) is a new
        // episode. De-escalation (critical -> warning) stays latched until clear.
        if (state.BreachedSeverity != null && state.BreachedSeverity >= severity)
            return;

        state.BreachedSeverity = severity;

        var label = string.IsNullOrEmpty(deviceName) ? deviceMac : deviceName;
        _logger.LogDebug("PoE budget threshold breached: {DeviceMac} draw={Draw:0.#}W of {Budget:0.#}W ({Pct:0.#}%)",
            deviceMac, totalW, budgetW, budgetPct);

        if (_eventBus == null)
            return;

        await _eventBus.PublishAsync(new AlertEvent
        {
            EventType = "monitoring.poe_budget",
            Source = "monitoring",
            Severity = severity.Value,
            Title = $"{label} PoE budget {(severity == AlertSeverity.Critical ? "critical" : "high")}",
            Message = $"{label} PoE draw is {totalW:0.#}W of its {budgetW:0.#}W budget ({budgetPct:0.#}%), " +
                      $"exceeding the {(severity == AlertSeverity.Critical ? CriticalThresholdPercent : WarnThresholdPercent):0}% threshold.",
            DeviceId = deviceMac,
            DeviceName = deviceName,
            MetricValue = budgetPct,
            ThresholdValue = severity == AlertSeverity.Critical ? CriticalThresholdPercent : WarnThresholdPercent,
            SourceUrl = "/monitoring?tab=devices",
            Tags = ["device", "poe"],
            Context = new Dictionary<string, string>
            {
                ["device_mac"] = deviceMac,
                ["metric"] = "poe_budget_pct",
                ["poe_total_w"] = totalW.ToString("0.##"),
                ["poe_budget_w"] = budgetW.ToString("0.##")
            }
        }, ct);
    }

    private class PoeBudgetState
    {
        public int ConsecutiveBreaches;
        public AlertSeverity? BreachedSeverity;
    }
}
