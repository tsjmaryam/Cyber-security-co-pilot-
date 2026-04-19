import { NextRequest } from "next/server";

import { GET, POST } from "./[...path]/route";

describe("agent proxy route", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("forwards auth GET requests to the agent backend", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ result: { auth_mode: "api_key" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const request = new NextRequest("http://127.0.0.1:3000/api/agent/incidents/incident-1/agent-auth");
    const response = await GET(request, {
      params: Promise.resolve({ path: ["incidents", "incident-1", "agent-auth"] }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8011/incidents/incident-1/agent-auth",
      expect.objectContaining({ method: "GET", redirect: "manual" }),
    );
    expect(response.status).toBe(200);
  });

  it("forwards agent query POST requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ result: { answer: "Use the stored recommendation." } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const request = new NextRequest("http://127.0.0.1:3000/api/agent/incidents/incident-1/agent-query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user_query: "What should I do?" }),
    });
    const response = await POST(request, {
      params: Promise.resolve({ path: ["incidents", "incident-1", "agent-query"] }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8011/incidents/incident-1/agent-query",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ user_query: "What should I do?" }),
      }),
    );
    expect(response.status).toBe(200);
  });
});
