import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => json((await (await ctx(req, "events:read")).engine()).metrics()));
