// Leaderboard Worker - Pharmacy Life (Cloudflare D1)
// Binding yang dibutuhkan: D1 database dengan nama variabel DB
// Tabel dibuat otomatis. Game (index.html) disajikan dari Static Assets Worker yang sama.
const MAX_SHOW = 100;
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json", ...CORS } });

let ready = false;
async function init(env) {
  if (ready) return;
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS leaderboard (id TEXT PRIMARY KEY, name TEXT NOT NULL, score INTEGER NOT NULL, lv INTEGER NOT NULL DEFAULT 1, updated INTEGER NOT NULL)"
  ).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_lb_score ON leaderboard (score DESC)").run();
  ready = true;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const isApi = url.pathname === "/scores" || url.pathname === "/score";

    if (!isApi) {
      if (env.ASSETS) return env.ASSETS.fetch(req);
      return json({ error: "Not found" }, 404);
    }
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    try {
      if (!env.DB) return json({ error: "Binding DB belum dipasang" }, 500);
      await init(env);

      // GET /scores?limit=10&me=<id>
      if (url.pathname === "/scores" && req.method === "GET") {
        const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit")) || 10, 1), MAX_SHOW);
        const me = url.searchParams.get("me") || "";
        const { results } = await env.DB.prepare(
          "SELECT id, name, score, lv FROM leaderboard ORDER BY score DESC, updated ASC LIMIT ?"
        ).bind(limit).all();
        return json(results.map((r) => ({ name: r.name, score: r.score, lv: r.lv, me: !!me && r.id === me })));
      }

      // POST /score  { id, name, score, lv }
      if (url.pathname === "/score" && req.method === "POST") {
        let b;
        try { b = await req.json(); } catch { return json({ error: "JSON tidak valid" }, 400); }

        const id = String(b.id ?? "").slice(0, 64);
        const name = String(b.name ?? "").trim().slice(0, 14) || "Apoteker";
        const score = Math.floor(Number(b.score));
        const lv = Math.max(1, Math.floor(Number(b.lv)) || 1);
        if (id.length < 8) return json({ error: "ID tidak valid" }, 400);
        if (!Number.isFinite(score) || score < 0 || score > 1e8) return json({ error: "Skor tidak valid" }, 400);

        await env.DB.prepare(
          `INSERT INTO leaderboard (id, name, score, lv, updated) VALUES (?1, ?2, ?3, ?4, ?5)
           ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             lv = excluded.lv,
             score = MAX(leaderboard.score, excluded.score),
             updated = excluded.updated`
        ).bind(id, name, score, lv, Date.now()).run();

        const row = await env.DB.prepare(
          "SELECT COUNT(*) + 1 AS rank FROM leaderboard WHERE score > (SELECT score FROM leaderboard WHERE id = ?)"
        ).bind(id).first();
        return json({ ok: true, rank: row ? row.rank : null });
      }

      return json({ error: "Method tidak didukung" }, 405);
    } catch (e) {
      return json({ error: "Server error" }, 500);
    }
  },
};
