# Detection Rules Library

A curated collection of production-ready detection rules for threat detection and incident response.

## Contents
- **50+ YARA Rules**: Malware detection, family identification, behavioral indicators
- **60+ Sigma Rules**: Generic detection rules (platform-agnostic) covering MITRE ATT&CK framework
- **40+ Splunk SPL**: Splunk-specific detection queries for log analysis
- **20+ KQL Rules**: Microsoft Sentinel/Defender detection rules

## Rule Categories
- Command & Control (C2) Detection
- Privilege Escalation Techniques
- Lateral Movement Indicators
- Data Exfiltration Patterns
- Persistence Mechanisms
- Defense Evasion Tactics

## Example Sigma Rule
```yaml
title: Process Injection via CreateRemoteThread
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - CreateRemoteThread
            - WriteProcessMemory
    filter:
        Image|endswith:
            - 'debugger.exe'
            - 'system32\svchost.exe'
    condition: selection and not filter
```

## Validation
All rules tested against:
- MITRE ATT&CK scenarios
- Real-world attack samples
- False positive reduction

## Integration
- Splunk Enterprise/Cloud
- Elastic/Kibana
- ArcSight
- Sumologic
- Datadog
