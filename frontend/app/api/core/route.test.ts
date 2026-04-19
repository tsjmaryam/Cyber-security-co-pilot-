import { NextRequest } from "next/server";

import { GET, POST } from "./[...path]/route";

describe("core proxy route", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("forwards GET requests to the backend base URL", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ incidents: [] }), {
        status: 200,
        headers: { "content-type": "application/json", "x-upstream": "core" },
      }),
    );

    const request = new NextRequest("http://127.0.0.1:3000/api/core/incidents?limit=5");
    const response = await GET(request, { params: Promise.resolve({ path: ["incidents"] }) });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8012/incidents?limit=5",
      expect.objectContaining({
        method: "GET",
        redirect: "manual",
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("x-upstream")).toBe("core");
  });

  it("forwards POST bodies to the backend", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ result: { decision_type: "approve_recommendation" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const request = new NextRequest("http://127.0.0.1:3000/api/core/incidents/incident-1/approve", {
      method: "POST",
      headers: { "content-type": "application/json", "x-request-id": "req-core-1" },
      body: JSON.stringify({ rationale: "Looks valid" }),
    });
    const response = await POST(request, {
      params: Promise.resolve({ path: ["incidents", "incident-1", "approve"] }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8012/incidents/incident-1/approve",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ rationale: "Looks valid" }),
      }),
    );
    expect(response.status).toBe(200);
  });
});
