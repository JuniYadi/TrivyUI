import type { Database } from "bun:sqlite";

interface CreateApiKeyRow {
  id: number;
  label: string;
  masked_key: string;
  created_at: string;
}

interface ApiKeyRecord {
  id: number;
  label: string;
  key_hash: string;
  key_prefix: string;
  masked_key: string;
  is_active: number;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface ApiKeyListItem {
  id: number;
  label: string;
  masked_key: string;
  is_active: boolean;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface CreatedApiKey {
  id: number;
  label: string;
  api_key: string;
  masked_key: string;
  created_at: string;
}

function generatePlaintextApiKey(): string {
  const token = Bun.randomUUIDv7("base64url").replace(/[^a-zA-Z0-9]/g, "").slice(0, 32);
  return `trivy_${token}`;
}

function buildMaskedKey(fullKey: string): { keyPrefix: string; maskedKey: string } {
  const visiblePrefixLength = Math.min(12, fullKey.length);
  const prefix = fullKey.slice(0, visiblePrefixLength);
  const maskedTail = "*".repeat(Math.max(8, fullKey.length - visiblePrefixLength));
  return {
    keyPrefix: prefix,
    maskedKey: `${prefix}${maskedTail}`,
  };
}

export async function createApiKey(db: Database, label: string): Promise<CreatedApiKey> {
  const apiKey = generatePlaintextApiKey();
  const keyHash = await Bun.password.hash(apiKey);
  const { keyPrefix, maskedKey } = buildMaskedKey(apiKey);

  const inserted = db
    .query("INSERT INTO api_keys (label, key_hash, key_prefix, masked_key, is_active) VALUES (?1, ?2, ?3, ?4, 1)")
    .run(label.trim(), keyHash, keyPrefix, maskedKey);

  const row = db.query("SELECT id, label, masked_key, created_at FROM api_keys WHERE id = ?1").get(Number(inserted.lastInsertRowid)) as
    | CreateApiKeyRow
    | null;

  if (!row) {
    throw new Error("FAILED_TO_CREATE_API_KEY");
  }

  return {
    id: row.id,
    label: row.label,
    api_key: apiKey,
    masked_key: row.masked_key,
    created_at: row.created_at,
  };
}

export function listApiKeys(db: Database): ApiKeyListItem[] {
  const rows = db
    .query(
      "SELECT id, label, masked_key, is_active, created_at, last_used_at, revoked_at FROM api_keys ORDER BY created_at DESC, id DESC"
    )
    .all() as ApiKeyRecord[];

  return rows.map((row) => ({
    id: row.id,
    label: row.label,
    masked_key: row.masked_key,
    is_active: row.is_active === 1,
    created_at: row.created_at,
    last_used_at: row.last_used_at,
    revoked_at: row.revoked_at,
  }));
}

export function revokeApiKey(db: Database, id: number): boolean {
  const result = db
    .query("UPDATE api_keys SET is_active = 0, revoked_at = CURRENT_TIMESTAMP WHERE id = ?1 AND is_active = 1")
    .run(id);
  return Number(result.changes) > 0;
}

export function getActiveApiKeyRecords(db: Database): ApiKeyRecord[] {
  return db
    .query("SELECT id, label, key_hash, key_prefix, masked_key, is_active, created_at, last_used_at, revoked_at FROM api_keys WHERE is_active = 1")
    .all() as ApiKeyRecord[];
}

export function touchApiKeyLastUsedAt(db: Database, id: number): void {
  db.query("UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?1").run(id);
}
