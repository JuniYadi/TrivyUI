export type SeverityKey = "critical" | "high" | "medium" | "low" | "unknown";

export const SEVERITY: Record<SeverityKey, { letter: string; label: string; bg: string; fg: string; bar: string }> = {
  critical: { letter: "C", label: "Critical", bg: "#3A1520", fg: "#FF7A93", bar: "#FF5C7A" },
  high: { letter: "H", label: "High", bg: "#3A2412", fg: "#F7A462", bar: "#F28C38" },
  medium: { letter: "M", label: "Medium", bg: "#3A3210", fg: "#EBCB66", bar: "#E5C04B" },
  low: { letter: "L", label: "Low", bg: "#132B3D", fg: "#7DBDEB", bar: "#5AA9E6" },
  unknown: { letter: "?", label: "Unknown", bg: "#1F2630", fg: "#C4CBD6", bar: "#8B95A5" },
};

export function toSeverityKey(value: string | null | undefined): SeverityKey {
  const key = (value ?? "").trim().toLowerCase();
  return key in SEVERITY ? (key as SeverityKey) : "unknown";
}
