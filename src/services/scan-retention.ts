export interface RetentionRule {
  repository: string | null;
  pattern: string;
  keep: number | null;
  index: number;
}

export interface RetentionPolicy {
  enabled: boolean;
  defaultKeep: number | null;
  groupRules: RetentionRule[];
  repoRules: RetentionRule[];
}

export function loadRetentionPolicyFromEnv(): RetentionPolicy {
  const enabled = (process.env.RETENTION_ENABLED || "false").trim().toLowerCase() === "true";
  const defaultKeep = parseKeep((process.env.RETENTION_DEFAULT_KEEP || "unlimited").trim());
  const groupRules = parseRules((process.env.RETENTION_GROUP_RULES || "").trim(), false);
  const repoRules = parseRules((process.env.RETENTION_REPO_RULES || "").trim(), true);

  return {
    enabled,
    defaultKeep: defaultKeep === undefined ? null : defaultKeep,
    groupRules,
    repoRules,
  };
}

export function resolveRetentionKeep(policy: RetentionPolicy, repository: string, tagGroup: string): number | null {
  if (!policy.enabled) {
    return null;
  }

  const repoRule = pickBestRule(policy.repoRules, repository, tagGroup);
  if (repoRule) {
    return repoRule.keep;
  }

  const groupRule = pickBestRule(policy.groupRules, repository, tagGroup);
  if (groupRule) {
    return groupRule.keep;
  }

  return policy.defaultKeep;
}

function parseRules(input: string, requiresRepo: boolean): RetentionRule[] {
  if (!input) {
    return [];
  }

  const entries = input
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);

  const rules: RetentionRule[] = [];

  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    const colon = entry.lastIndexOf(":");
    if (colon < 1 || colon === entry.length - 1) {
      continue;
    }

    const lhs = entry.slice(0, colon).trim();
    const rhs = entry.slice(colon + 1).trim();
    const keep = parseKeep(rhs);

    if (keep === undefined) {
      continue;
    }

    if (requiresRepo) {
      const slash = lhs.lastIndexOf("/");
      if (slash < 1 || slash === lhs.length - 1) {
        continue;
      }

      rules.push({
        repository: lhs.slice(0, slash).trim().toLowerCase(),
        pattern: lhs.slice(slash + 1).trim().toLowerCase(),
        keep,
        index: i,
      });
      continue;
    }

    rules.push({
      repository: null,
      pattern: lhs.toLowerCase(),
      keep,
      index: i,
    });
  }

  return rules;
}

function parseKeep(value: string): number | null | undefined {
  const normalized = value.trim().toLowerCase();
  if (normalized === "unlimited") {
    return null;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return undefined;
  }

  return parsed;
}

function pickBestRule(rules: RetentionRule[], repository: string, tagGroup: string): RetentionRule | null {
  const repositoryNorm = repository.trim().toLowerCase();
  const tagGroupNorm = (tagGroup || "ungrouped").trim().toLowerCase();
  const matches = rules.filter((rule) => {
    if (rule.repository && rule.repository !== repositoryNorm) {
      return false;
    }

    return wildcardMatch(tagGroupNorm, rule.pattern);
  });

  if (matches.length === 0) {
    return null;
  }

  matches.sort((a, b) => {
    const scoreA = specificityScore(a.pattern);
    const scoreB = specificityScore(b.pattern);

    if (scoreA !== scoreB) {
      return scoreB - scoreA;
    }

    return a.index - b.index;
  });

  return matches[0] ?? null;
}

function wildcardMatch(value: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  const regex = new RegExp(`^${escaped}$`, "i");
  return regex.test(value);
}

function specificityScore(pattern: string): number {
  const literalLength = pattern.replace(/\*/g, "").length;
  const wildcardPenalty = (pattern.match(/\*/g) || []).length;
  return literalLength * 10 - wildcardPenalty;
}
