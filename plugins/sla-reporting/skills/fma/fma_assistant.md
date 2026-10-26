---
name: azure-fma-analysis
description: Use this skill when the user needs Azure Failure Mode Analysis for a workload, critical flow, Azure resource list, dependency map, or CSV-based FMA table.
owner: Dave Newman
---

# Azure Failure Mode Analysis Skill

## Purpose
Assist users in performing Failure Mode Analysis for Azure workload resources, connect each analysis row to the Microsoft Azure Well-Architected Framework, validate that the full critical flow is represented, and generate structured tabular outputs suitable for CSV or Excel.

## Invoke when
Use this skill when the user asks to:
- Perform FMA, failure mode analysis, FMEA, resiliency analysis, or reliability review for Azure resources.
- Analyze a critical flow or dependency chain.
- Expand an existing CSV of Azure resources into failure modes.
- Map failure modes to Azure Well-Architected Framework pillars or design areas.

## Do not invoke when
Do not use this skill for general Azure troubleshooting, cost analysis, migration planning, or deployment guidance unless the user explicitly asks for FMA-style failure mode analysis.

## Initial response
If the user has not provided resource details, ask:
"To get started, list the Azure resources in your critical flow by resource type. Include upstream, downstream, network, identity, data, and external dependencies if they are part of the flow."

If the user already provided resource details, use them directly.

## Required workflow
1. Identify the resources, dependencies, and critical path elements.
2. Check for missing upstream, downstream, network, identity, data, monitoring, and external dependencies.
3. Ask the confirmation prompt:
   "Have you included all dependencies in the critical flow, including upstream, downstream, network, identity, data, and external dependencies? If not, add any missing resources now. If the list is complete, reply 'Continue'."
4. When the user confirms, analyze each resource for realistic Azure-specific failure modes.
5. Include configuration, scale, network, security, backup, platform limits, dependency, and feature-level failures.
6. Provide impact, cause, mitigation, detection signal, severity, likelihood, WAF pillar, and WAF area.
7. Use the required output schema.

## Output schema
Always produce columns in this exact order:

ResourceType  
ComponentName  
FailureMode  
Scenario  
Impact  
Cause  
Mitigation  
DetectionSignal  
Severity  
Likelihood  
WellArchitectedPillar  
WellArchitectedArea  
Notes

## Severity values
Use only:
- Low
- Medium
- High
- Critical

## Likelihood values
Use only:
- Rare
- Unlikely
- Possible
- Likely
- Almost Certain
