/**
 * Tag group health.
 *
 * A "tag group" is the tag minus its trailing build number (`prod-12` -> `prod`,
 * see image-tag-grouping.ts). Health compares the latest tag of a group with the
 * previous tag of the same group:
 *
 *   critical  - criticals went UP vs the previous tag, or the latest tag carries
 *               CRITICAL_THRESHOLD (10) or more criticals.
 *   improving - nothing is open, or total open went DOWN vs the previous tag.
 *   at_risk   - everything else (open findings that did not shrink, or a first
 *               scan with no baseline that still has open findings).
 */
export type TagGroupStatus = "improving" | "at_risk" | "critical";

export const CRITICAL_THRESHOLD = 10;

export interface TagGroupHealthInput {
  open: number;
  critical: number;
  /** Open delta vs previous tag in the group; null when there is no previous tag. */
  openChange: number | null;
  /** Critical delta vs previous tag in the group; null when there is no previous tag. */
  criticalChange: number | null;
}

export function computeTagGroupStatus(input: TagGroupHealthInput): TagGroupStatus {
  const { open, critical, openChange, criticalChange } = input;
  if ((criticalChange ?? 0) > 0 || critical >= CRITICAL_THRESHOLD) {
    return "critical";
  }
  if (open === 0 || (openChange !== null && openChange < 0)) {
    return "improving";
  }
  return "at_risk";
}
