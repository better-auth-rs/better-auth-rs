import { expect, test } from "bun:test";
import { organizationNativeCase } from "./organization-native";

for (const backend of ["memory", "sqlite"]) {
  for (const mode of ["normal", "patch", "stop", "replace", "invalid", "override", "before-error", "after-error", "member-error", "policy-error", "limit", "team", "team-limit", "team-disabled", "missing-org", "duplicate", "tx-commit", "tx-rollback", "org-number", "team-dynamic-limit", "tx-team-commit", "tx-team-rollback", "tx-team-catch", "team-reassign", "tx-team-reassign"]) {
    test(`${backend}/${mode}`, async () => {
      const result = await organizationNativeCase(backend, mode);
      console.log(JSON.stringify({ backend, mode, ...result }));
      const success = ["normal", "patch", "replace", "team", "tx-commit", "tx-team-commit"].includes(mode);
      expect(result.members.length).toBe(success || ["after-error", "duplicate"].includes(mode) ? 1 : 0);
      expect(result.events[0].phase).toBe("before");
      expect(result.events[0].path).toBe("/");
      expect(result.events[0].ambient).toEqual({ $undefined: true });
      if (["stop", "replace"].includes(mode)) expect(result.result).toEqual({ [mode === "stop" ? "stopped" : "replaced"]: true });
      if (mode === "limit") expect(result.error.body.code).toBe("ORGANIZATION_MEMBERSHIP_LIMIT_REACHED");
      if (mode === "team-limit") expect(result.error.body.code).toBe("TEAM_MEMBER_LIMIT_REACHED");
      if (mode === "invalid" || mode === "override") expect(result.error.body.code).toBe("VALIDATION_ERROR");
      if (mode === "normal") expect(result.result).toMatchObject({ label: "sent:hook:in:out", secret: "hidden" });
      if (mode === "tx-rollback") expect(result.error).toEqual({ message: "rollback requested" });
      if (mode === "org-number") expect(result.error.body.code).toBe("ORGANIZATION_NOT_FOUND");
      if (mode === "team-dynamic-limit") expect(result.error).toEqual({ status: 401, body: undefined });
      if (mode === "tx-team-commit") expect(result.teams).toBe(1);
      if (mode === "tx-team-rollback" || mode === "tx-team-catch") expect(result.teams).toBe(0);
      if (mode.endsWith("reassign")) expect(result.ownerTeams).toBe(1);
    });
  }
}
