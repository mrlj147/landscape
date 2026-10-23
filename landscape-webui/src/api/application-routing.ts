import axios from "axios";
import { applyInterceptors } from "@/api";
import type {
  ApplicationCatalog,
  ApplicationRoutingStatus,
  ApplicationRule,
} from "@/lib/application_routing";

const client = applyInterceptors(
  axios.create({ baseURL: "/api/v1/dpi", timeout: 95000 }),
);
type Envelope<T> = { data: T };

export async function getApplicationRoutingStatus(): Promise<ApplicationRoutingStatus> {
  const response = await client.get<never, Envelope<ApplicationRoutingStatus>>(
    "/status",
    { timeout: 15000 },
  );
  return response.data;
}

export async function getApplicationCatalog(
  q: string,
  offset: number,
  limit = 20,
): Promise<ApplicationCatalog> {
  const response = await client.get<never, Envelope<ApplicationCatalog>>(
    "/catalog",
    { params: { q, offset, limit } },
  );
  return response.data;
}

export async function saveApplicationPolicy(
  expectedRevision: number,
  rules: ApplicationRule[],
): Promise<ApplicationRoutingStatus> {
  const response = await client.put<never, Envelope<ApplicationRoutingStatus>>(
    "/policy",
    { expected_revision: expectedRevision, rules },
  );
  return response.data;
}

export async function applyApplicationPolicy(
  revision: number,
  initialQuiescent: boolean,
): Promise<ApplicationRoutingStatus> {
  const response = await client.post<never, Envelope<ApplicationRoutingStatus>>(
    "/apply",
    { revision, initial_quiescent: initialQuiescent },
  );
  return response.data;
}

export async function stopApplicationPolicy(): Promise<ApplicationRoutingStatus> {
  const response = await client.post<never, Envelope<ApplicationRoutingStatus>>(
    "/stop",
    {},
  );
  return response.data;
}
