import { optionalUser } from "@/server/context";
import { fail, handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const { user, db } = await optionalUser(req);
  return user ? json({ user, db: db.driver }) : fail(401, "Not signed in");
});
