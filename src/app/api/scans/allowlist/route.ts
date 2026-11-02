import { ctx } from "@/server/context";
import { body, fail, handle, json } from "@/server/http";
import { validateAllowlistCidr } from "@/server/scan/policy";
import { addAllowlist, listAllowlist } from "@/server/scan/store";
import { AllowlistInput } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "scans:read");
  return json(await listAllowlist(c.db, c.user.orgId));
});

export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "scans:allowlist");
  const { cidr, label } = await body(req, AllowlistInput);
  const v = validateAllowlistCidr(cidr, { allowPublic: process.env.SCAN_ALLOW_PUBLIC === "1" });
  if (!v.ok) return fail(422, v.error);
  const id = await addAllowlist(c.db, c.user.orgId, v.network, label, c.user.name);
  await c.audit("scan.allowlist_add", v.network, { label });
  return json({ id, cidr: v.network }, { status: 201 });
});
