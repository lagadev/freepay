/**
 * FreePay — single-Worker entry point.
 *
 * One `wrangler deploy`, one Worker, one origin. Routes starting with /api/
 * go to the JSON API (api.js); everything else is served straight out of
 * pages.generated.js (built by build-pages.js from src/pages/raw/).
 */
import { handleApi, corsHeaders, json } from "./api.js";
import { PAGES } from "./pages.generated.js";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders() });

    // convenience redirect
    if (pathname === "/app" || pathname === "/app/") {
      return Response.redirect(url.origin + "/app/login.html", 302);
    }

    if (pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, ctx, url);
      } catch (err) {
        return json({ error: "Internal error.", detail: String(err && err.message) }, 500);
      }
    }

    const page = PAGES[pathname];
    if (page && request.method === "GET") {
      return new Response(page.body, {
        status: 200,
        headers: { "Content-Type": page.contentType, "Cache-Control": pathname.startsWith("/assets/") ? "public, max-age=300" : "no-cache" },
      });
    }

    return new Response("Not found.", { status: 404, headers: { "Content-Type": "text/plain" } });
  },
};
