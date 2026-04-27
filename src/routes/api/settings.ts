import type { Database } from "bun:sqlite";
import {
  getNotificationSettings,
  parseMinSeverity,
  updateNotificationSettings,
  type NotificationMinSeverity,
} from "../../services/notification";
import { ApiError, buildSuccessResponse, sendError, toApiError } from "./_shared";

interface NotificationSettingsPayload {
  enabled: boolean;
  min_severity: NotificationMinSeverity;
}

export function createNotificationSettingsHandler(db: Database) {
  return async function notificationSettingsHandler(request: Request): Promise<Response> {
    try {
      if (request.method === "GET") {
        const settings = getNotificationSettings(db);
        return buildSuccessResponse<NotificationSettingsPayload>({
          enabled: settings.enabled,
          min_severity: settings.minSeverity,
        });
      }

      if (request.method !== "PUT") {
        throw new ApiError(405, "METHOD_NOT_ALLOWED", `Method ${request.method} is not allowed for /api/settings/notifications`);
      }

      const body = (await request.json()) as { enabled?: unknown; min_severity?: unknown };

      if (typeof body.enabled !== "boolean") {
        throw new ApiError(400, "INVALID_REQUEST", "'enabled' must be a boolean");
      }

      const minSeverity = parseMinSeverity(typeof body.min_severity === "string" ? body.min_severity : undefined);
      if (typeof body.min_severity !== "string") {
        throw new ApiError(400, "INVALID_REQUEST", "'min_severity' must be one of CRITICAL|HIGH|MEDIUM|LOW");
      }

      if (minSeverity !== body.min_severity.toUpperCase()) {
        throw new ApiError(400, "INVALID_REQUEST", "'min_severity' must be one of CRITICAL|HIGH|MEDIUM|LOW");
      }

      const updated = updateNotificationSettings(db, {
        enabled: body.enabled,
        minSeverity,
      });

      return buildSuccessResponse<NotificationSettingsPayload>({
        enabled: updated.enabled,
        min_severity: updated.minSeverity,
      });
    } catch (error) {
      const normalized = toApiError(error);
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
