/**
 * GuardLink Threat Reports — Framework-specific analysis prompts.
 *
 * Each framework produces a structured security analysis from the
 * serialized threat model. The LLM acts as a senior security architect.
 */

export type AnalysisFramework = 'stride' | 'dread' | 'pasta' | 'attacker' | 'rapid' | 'general';

export const FRAMEWORK_LABELS: Record<AnalysisFramework, string> = {
  stride: 'STRIDE Threat Analysis',
  dread: 'DREAD Risk Assessment',
  pasta: 'PASTA Attack Simulation',
  attacker: 'Attacker Persona Analysis',
  rapid: 'Rapid Risk Assessment',
  general: 'General Threat Analysis',
};

const SYSTEM_BASE = `You are an expert Security Architect and Threat Modeler with 15+ years of experience.
You are analyzing a codebase that uses GuardLink annotations — structured security metadata embedded in source code comments.

The threat model you receive contains:
- **Assets**: Components declared by developers
- **Threats**: Known threat vectors with severity and CWE references
- **Controls**: Security mechanisms in place
- **Mitigations**: Where controls defend assets against threats
- **Exposures**: Known vulnerabilities (asset exposed to threat)
- **Flows**: Data movement between components
- **Boundaries**: Trust boundaries between security zones
- **Comments**: Developer security notes

Your analysis must be actionable, specific to THIS codebase, and reference the actual assets/threats/controls by name.
Never give generic advice — always tie recommendations to concrete annotations in the model.`;

export const FRAMEWORK_PROMPTS: Record<AnalysisFramework, string> = {
  stride: `${SYSTEM_BASE}

Perform a **STRIDE** analysis of this threat model.

For each STRIDE category, evaluate the codebase:

## S — Spoofing
Identify where authentication can be bypassed. Check: are all assets with @exposes to auth-related threats properly mitigated?

## T — Tampering
Identify where data integrity is at risk. Check: @flows without integrity controls, @handles with sensitive data lacking validation.

## R — Repudiation
Identify where actions cannot be traced. Check: are there @audit annotations? Are critical operations logged?

## I — Information Disclosure
Identify where sensitive data leaks. Check: @exposes to info-disclosure/data-exposure threats, @handles pii/phi/secrets without encryption.

## D — Denial of Service
Identify resource exhaustion risks. Check: @exposes to dos threats, rate limiting controls, boundary protections.

## E — Elevation of Privilege
Identify privilege escalation paths. Check: @exposes to bac/idor threats, @boundary gaps, missing authorization controls.

For each category:
1. List specific findings referencing actual assets and threats from the model
2. Rate severity (Critical/High/Medium/Low)
3. Recommend specific mitigations referencing existing controls or suggesting new ones
4. Identify gaps — what SHOULD be annotated but isn't?

End with an Executive Summary and Priority Action Items.`,

  dread: `${SYSTEM_BASE}

Perform a **DREAD** risk scoring analysis of this threat model.

For each unmitigated exposure and significant threat, calculate a DREAD score:

- **D — Damage Potential** (0-10): How bad if exploited?
- **R — Reproducibility** (0-10): How easy to reproduce?
- **E — Exploitability** (0-10): How easy to launch the attack?
- **A — Affected Users** (0-10): How many users impacted?
- **D — Discoverability** (0-10): How easy to find the vulnerability?

Present results as a ranked table:

| Threat | Asset | D | R | E | A | D | Total | Risk Level |
|--------|-------|---|---|---|---|---|-------|------------|

Then provide:
1. Top 5 risks by DREAD score with detailed justification
2. Quick wins — high-score items with easy mitigations
3. Systemic risks — patterns across multiple exposures
4. Recommended priority order for remediation`,

  pasta: `${SYSTEM_BASE}

Perform a **PASTA** (Process for Attack Simulation and Threat Analysis) assessment.

Work through all 7 PASTA stages:

### Stage 1: Define Objectives
What are the business-critical assets? Which @asset declarations represent the crown jewels?

### Stage 2: Define Technical Scope
Map the attack surface from @flows, @boundary, and @handles annotations. What are the entry points?

### Stage 3: Application Decomposition
Analyze component relationships from flows and boundaries. Identify trust zones and data paths.

### Stage 4: Threat Analysis
Map declared @threat annotations to real-world attack techniques. Reference CWE/CAPEC where available.

### Stage 5: Vulnerability Analysis
Evaluate each @exposes annotation. Which are most exploitable given the technical context?

### Stage 6: Attack Simulation
For the top 3 most critical exposures, describe a realistic attack scenario step-by-step.

### Stage 7: Risk & Impact Analysis
Prioritized risk matrix with business impact assessment.

End with concrete remediation recommendations tied to specific annotations.`,

  attacker: `${SYSTEM_BASE}

Perform an **Attacker Persona** analysis of this threat model.

Adopt the mindset of different attacker types and evaluate the codebase:

### 1. Script Kiddie (Low Skill)
What can be exploited with publicly available tools? Which @exposes have known CVEs (check cwe: refs)?

### 2. Opportunistic Attacker (Medium Skill)
What attack chains are possible? Can multiple exposures be combined? Check @flows for lateral movement paths.

### 3. Targeted Attacker (High Skill)
What are the high-value targets (@handles pii/phi/financial/secrets)? What's the path from @boundary entry points to crown jewel assets?

### 4. Insider Threat
Which @assumes annotations represent blind spots? Where does the model trust internal components without verification?

For each persona:
1. Most likely attack vector (reference specific annotations)
2. Attack path (chain of assets/flows/boundaries)
3. Impact if successful
4. Current defenses (existing @mitigates)
5. Gaps in defense

End with a prioritized defense improvement plan.`,

  rapid: `${SYSTEM_BASE}

Perform a **Rapid Risk Assessment** — concise, actionable, focused on the highest-impact items.

### Critical Findings (Stop Everything)
List any P0/critical @exposes without @mitigates. These are active vulnerabilities.

### High-Priority Gaps
- Unmitigated exposures by severity
- @assumes that could be violated
- @boundary without proper controls on crossing flows

### Coverage Assessment
- What percentage of assets have threat coverage?
- Which components have @flows but no security annotations?
- Are there @handles (sensitive data) without corresponding @mitigates?

### Top 5 Recommendations
Numbered, actionable, with specific annotation suggestions (exact @mitigates lines to add).

### Risk Score
Rate overall security posture: A (excellent) through F (critical risk). Justify with data from the model.

Keep the entire analysis under 500 lines. Be direct — no filler.`,

  general: `${SYSTEM_BASE}

Perform a comprehensive threat analysis of this codebase.

### Executive Summary
2-3 sentence overall assessment.

### Threat Landscape
What threats does this application face? Map @threat declarations to real-world attack patterns.

### Security Posture
- Strengths: well-mitigated areas, good control coverage
- Weaknesses: unmitigated exposures, missing controls
- Blind spots: areas with no annotations at all

### Data Flow Analysis
Trace sensitive data through @flows and @boundary annotations. Where does data cross trust boundaries without protection?

### Missing Annotations
Based on the architecture visible in @flows and @boundary, what security annotations are likely missing?

### Recommendations
Prioritized list with:
1. What to fix (specific exposure)
2. How to fix it (specific control/mitigation)
3. What annotation to add (exact syntax)

### Compliance Considerations
Based on @handles classifications (pii, phi, financial), note relevant compliance requirements (GDPR, HIPAA, PCI-DSS).`,
};

/**
 * Build the user message containing the serialized threat model.
 */
export function buildUserMessage(modelJson: string, framework: AnalysisFramework, customPrompt?: string): string {
  const header = customPrompt
    ? `Analyze this threat model. ${customPrompt}`
    : `Produce a ${FRAMEWORK_LABELS[framework]} for this threat model.`;

  return `${header}

<threat_model>
${modelJson}
</threat_model>`;
}
