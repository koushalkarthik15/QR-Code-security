import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "crypto";

const BACKEND_BASE =
  process.env.QRSHIELD_API_BASE ||
  process.env.NEXT_PUBLIC_QRSHIELD_API_BASE ||
  "https://qr-code-security.vercel.app/";
const BACKEND_API_KEY = process.env.QRSHIELD_API_KEY || "";
const CLIENT_API_KEY =
  process.env.QRSHIELD_CLIENT_API_KEY ||
  process.env.NEXT_PUBLIC_QRSHIELD_CLIENT_API_KEY ||
  "";

function errorPayload(message: string, details?: unknown) {
  return {
    status: "error",
    request_id: crypto.randomUUID(),
    timestamp_utc: new Date().toISOString(),
    error: { message, details }
  };
}

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

function clientIsAuthorized(req: NextRequest): boolean {
  const incoming = req.headers.get("x-api-key") || "";
  return constantTimeEquals(incoming, CLIENT_API_KEY);
}

export async function forwardPost(
  req: NextRequest,
  backendPath: string
): Promise<NextResponse> {
  if (!CLIENT_API_KEY) {
    return NextResponse.json(
      errorPayload("Server is missing client API key configuration."),
      { status: 500 }
    );
  }

  if (!clientIsAuthorized(req)) {
    return NextResponse.json(errorPayload("Unauthorized."), { status: 401 });
  }

  if (!BACKEND_API_KEY) {
    return NextResponse.json(
      errorPayload("Server is missing QRShield API key configuration."),
      { status: 500 }
    );
  }

  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json(errorPayload("Invalid JSON request body."), {
      status: 400
    });
  }

  const endpoint = `${BACKEND_BASE}${backendPath}`;

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": BACKEND_API_KEY
      },
      cache: "no-store",
      body: JSON.stringify(payload)
    });

    const data = await response.json().catch(() =>
      errorPayload("Backend returned non-JSON response.")
    );

    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json(
      errorPayload("Failed to reach QRShield backend."),
      { status: 502 }
    );
  }
}
