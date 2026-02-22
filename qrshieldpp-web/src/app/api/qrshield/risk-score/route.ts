import { NextRequest } from "next/server";

import { forwardPost } from "../_shared";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  return forwardPost(req, "/risk/score");
}

