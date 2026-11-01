export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let csrf = "";

export function setCsrf(token: string) {
  csrf = token;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (init.method && init.method !== "GET" && csrf) headers.set("X-CSRF-Token", csrf);
  const response = await fetch(`/api/v1${path}`, { credentials: "include", ...init, headers });
  if (response.status === 401) throw new ApiError(401, "Authentication is required.");
  if (!response.ok) {
    const text = await response.text();
    throw new ApiError(response.status, text);
  }
  if (response.headers.get("content-type")?.includes("application/json")) return response.json() as Promise<T>;
  return response as unknown as T;
}

export type Me = { username: string; roles: string[]; csrf_token: string; permissions: string[] };
export type Status = {
  status: string;
  database: boolean;
  keycloak: boolean;
  downstream: boolean;
  environment: string;
  organisation: string;
  identities: number;
  open_findings: number;
  open_reviews: number;
  policy_version: string;
};

export function can(me: Me | undefined, permission: string) {
  return Boolean(me?.permissions.includes(permission));
}
