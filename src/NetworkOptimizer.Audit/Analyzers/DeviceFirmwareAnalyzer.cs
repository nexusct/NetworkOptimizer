using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetworkOptimizer.Audit.Models;
using NetworkOptimizer.Audit.Scoring;
using NetworkOptimizer.Core.Helpers;

namespace NetworkOptimizer.Audit.Analyzers;

/// <summary>
/// Analyzes device firmware state from /stat/device JSON.
/// Flags devices the console reports as upgradable (firmware update available) and
/// devices whose model is end-of-life (no further firmware updates).
/// </summary>
public class DeviceFirmwareAnalyzer
{
    private readonly ILogger<DeviceFirmwareAnalyzer> _logger;

    public DeviceFirmwareAnalyzer(ILogger<DeviceFirmwareAnalyzer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyze device firmware state.
    /// </summary>
    /// <param name="deviceData">Raw device data JSON from /stat/device</param>
    /// <returns>List of audit issues found</returns>
    public List<AuditIssue> Analyze(JsonElement deviceData)
    {
        var issues = new List<AuditIssue>();

        if (deviceData.ValueKind is not (JsonValueKind.Array or JsonValueKind.Object))
            return issues;

        foreach (var device in deviceData.UnwrapDataArray())
        {
            // Skip devices that were never adopted - not managed by this console
            if (device.TryGetProperty("adopted", out var adoptedEl) &&
                adoptedEl.ValueKind is JsonValueKind.False)
                continue;

            var upgradable = device.GetBoolOrDefault("upgradable");
            var modelInEol = device.GetBoolOrDefault("model_in_eol");

            if (!upgradable && !modelInEol)
                continue;

            var name = device.GetStringOrNull("name");
            var model = device.GetStringOrNull("model");
            var shortname = device.GetStringOrNull("shortname");
            var friendlyModel = UniFi.UniFiProductDatabase.GetBestProductName(model, shortname);
            var deviceName = !string.IsNullOrEmpty(name)
                ? $"{name} ({friendlyModel})"
                : friendlyModel;
            var currentVersion = device.GetStringOrNull("displayable_version")
                ?? device.GetStringOrNull("version");
            var targetVersion = device.GetStringOrNull("upgrade_to_firmware");

            var metadata = new Dictionary<string, object>
            {
                ["device_name"] = name ?? "Unknown",
                ["model"] = friendlyModel,
                ["mac"] = device.GetStringOrNull("mac") ?? "",
                ["upgradable"] = upgradable,
                ["model_in_eol"] = modelInEol
            };
            if (!string.IsNullOrEmpty(currentVersion))
                metadata["current_firmware"] = currentVersion;
            if (!string.IsNullOrEmpty(targetVersion))
                metadata["available_firmware"] = targetVersion;

            if (modelInEol)
            {
                // EOL devices no longer receive firmware updates, including security fixes.
                // This supersedes the plain "update available" finding for the same device.
                issues.Add(new AuditIssue
                {
                    Type = IssueTypes.FirmwareEol,
                    Severity = AuditSeverity.Critical,
                    Message = $"{deviceName} is an end-of-life model no longer receiving firmware or security updates{(currentVersion != null ? $" (running {currentVersion})" : "")}",
                    DeviceName = deviceName,
                    DeviceMac = device.GetStringOrNull("mac"),
                    Metadata = metadata,
                    RuleId = IssueTypes.FirmwareEol,
                    ScoreImpact = ScoreConstants.CriticalImpact,
                    RecommendedAction = "This model is end-of-life and no longer receives security patches from Ubiquiti. Plan to replace it with a currently supported model; until then, isolate it on a restricted network and disable any remote access features."
                });
            }
            else
            {
                var versionDetail = currentVersion != null && targetVersion != null
                    ? $" ({currentVersion} → {targetVersion})"
                    : currentVersion != null ? $" (running {currentVersion})" : "";

                issues.Add(new AuditIssue
                {
                    Type = IssueTypes.FirmwareOutdated,
                    Severity = AuditSeverity.Recommended,
                    Message = $"{deviceName} has a firmware update available{versionDetail}",
                    DeviceName = deviceName,
                    DeviceMac = device.GetStringOrNull("mac"),
                    Metadata = metadata,
                    RuleId = IssueTypes.FirmwareOutdated,
                    ScoreImpact = ScoreConstants.RecommendedImpact,
                    RecommendedAction = "Update the device firmware in UniFi Network > Devices. Firmware updates routinely patch security vulnerabilities in the device OS and management services."
                });
            }
        }

        _logger.LogInformation("Device firmware analysis: {IssueCount} issues", issues.Count);
        return issues;
    }
}
