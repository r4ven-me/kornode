/** Agent roles (D-84): `gateway` was called `exit` before. */
export const AGENT_ROLES = ["access", "gateway"] as const;
export const ROLE_HINTS: Record<(typeof AGENT_ROLES)[number], string> = {
  access: "Serves its own VPN clients",
  gateway: "Other nodes may leave to the internet through it (via node:<id>)"
};
