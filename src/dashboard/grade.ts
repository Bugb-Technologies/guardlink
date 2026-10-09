/**
 * GuardLink Dashboard — the A–F risk grade.
 *
 * Kept, and demoted: the Overview leads with how many exposures are open and
 * how many of those are critical or high, and the grade sits beside that
 * sentence as a small tag. It grades what is still open; a mitigated critical
 * is not a critical risk.
 */
import type { SeverityBreakdown } from './data.js';

export function computeRiskGrade(sev: SeverityBreakdown, unmitigatedCount: number, totalExposures: number, confirmedCount = 0): { grade: string; label: string; summary: string } {
  if (confirmedCount > 0) return { grade: 'F', label: 'Critical Risk', summary: `${confirmedCount} confirmed exploitable finding(s) — immediate remediation required` };
  if (sev.critical > 0) return { grade: 'F', label: 'Critical Risk', summary: `${sev.critical} critical exposure(s) require immediate attention` };
  if (sev.high >= 3 || unmitigatedCount >= 5) return { grade: 'D', label: 'High Risk', summary: `${unmitigatedCount} unmitigated exposure(s), ${sev.high} high severity` };
  if (sev.high >= 1 || unmitigatedCount >= 3) return { grade: 'C', label: 'Moderate Risk', summary: `${unmitigatedCount} unmitigated exposure(s) need remediation` };
  if (unmitigatedCount >= 1) return { grade: 'B', label: 'Low Risk', summary: `${unmitigatedCount} minor unmitigated exposure(s)` };
  if (totalExposures === 0) return { grade: 'A', label: 'Excellent', summary: 'No exposures detected — consider adding more annotations' };
  return { grade: 'A', label: 'Excellent', summary: 'All exposures mitigated or accepted' };
}
