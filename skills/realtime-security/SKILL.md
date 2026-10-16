---
name: realtime-security
description: Audits WebSocket servers (ws, Socket.IO, Hono upgradeWebSocket, Next.js custom-server 'upgrade' handlers), Server-Sent Events (streamSSE, EventSource) and long-poll endpoints. Covers cross-site WebSocket hijacking and the Origin allowlist, tokens in URLs vs single-use tickets, sockets that outlive logout or revocation, room/channel IDOR, per-message authorization, Last-Event-ID replay across tenants, per-subscriber pub/sub fan-out, payload and connection limits, SSE proxy buffering, and 2024-2026 ws, socket.io, engine.io and Hono advisories. Use whenever the project imports ws or socket.io, calls upgradeWebSocket/streamSSE, listens for 'upgrade', or serves text/event-stream. Hand-offs: secaudit:proxy-trust (client IPs), secaudit:rate-limiting, secaudit:auth (sessions), secaudit:postgres-security (LISTEN/NOTIFY internals).
license: MIT
---

# Realtime Security (WebSocket, SSE, Long-Poll)

A realtime connection is checked once and then *stays open* for hours, carrying messages no route
middleware sees again. The session can be revoked, the user kicked, their role dropped — and the
socket they opened before any of that keeps receiving the community's events.

The recurring AI-codegen failure mode is a realtime feature that works in the demo. The WebSocket
handler reads the session cookie and starts streaming — nobody asked which *page* opened the
socket, though the browser sends that cookie on a cross-site upgrade and WebSocket has no CORS to
stop the attacker's page reading replies. The SSE endpoint takes `?token=` because `EventSource`
can't send headers, and the token lands in every access log. The client sends
`{ type: 'subscribe', communityId: 42 }` and the server joins it without asking whether this user
belongs to community 42. One `LISTEN` connection fans every tenant's events out to every socket.
None of these fail a happy-path test.

Findings map to OWASP **A01:2025** (Broken Access Control — CSWSH, room IDOR, cross-tenant fan-out
and replay), **A07:2025** (Authentication Failures — URL tokens, connections outliving the
session), **A02:2025** (Security Misconfiguration — permissive origin/CORS, default limits),
**A06:2025** (Insecure Design — no per-connection resource model), and **A10:2025** (Mishandling of
Exceptional Conditions — unhandled `'error'` events, exception text streamed to clients).

## When to Use

- The project depends on `ws`, `socket.io`, `engine.io`, `@hono/node-ws`, or `@hono/node-server`
  v2's `websocket` option, or calls `upgradeWebSocket` from any Hono adapter.
- Code listens for the Node HTTP server's `'upgrade'` event (common in Next.js custom servers).
- A route returns `text/event-stream`, front-end code constructs `new EventSource(...)` or
  `new WebSocket(...)`, or an endpoint holds a request open until something happens (long-poll).
- Server code subscribes to a shared bus (Postgres `LISTEN`, Redis `SUBSCRIBE`/`PSUBSCRIBE`) and
  forwards to connected clients.

Review grep heuristics:

```bash
grep -rnE "from ['\"](ws|socket\.io|engine\.io|@hono/node-ws)['\"]|upgradeWebSocket|streamSSE|new (WebSocketServer|EventSource|WebSocket)\(" \
  --include='*.ts' --include='*.tsx' --include='*.js' .
grep -rnE "on\(['\"]upgrade['\"]|handleUpgrade|verifyClient|allowRequest|noServer|skipMiddlewares" --include='*.ts' --include='*.js' .
grep -rnE "text/event-stream|Last-Event-ID|last-event-id|cursor" --include='*.ts' --include='*.js' .
grep -rnE "maxPayload|maxHttpBufferSize|maxFragments|maxBufferedChunks|perMessageDeflate|bufferedAmount" --include='*.ts' --include='*.js' .
grep -rnE "\.join\(|socket\.on\(['\"](subscribe|join)|io\.of\(" --include='*.ts' --include='*.js' .
grep -rnE "LISTEN |on\(['\"]notification['\"]|psubscribe|PSUBSCRIBE" --include='*.ts' --include='*.js' .
grep -rnE "[?&](token|access_token|api_key|apikey|jwt)=|handshake\.query\.(token|jwt)" --include='*.ts' --include='*.tsx' --include='*.js' .
```

## 1. Cross-Site WebSocket Hijacking and the Origin Allowlist

**What to look for:** an upgrade authenticated by the session cookie with no `Origin` check;
Socket.IO with `cors: { origin: [...] }` and nothing else, assumed to cover WebSockets; an origin
check written as `endsWith`, `includes`, or an unanchored regex.

**Why it's exploitable:** the browser's WebSocket request uses credentials mode `"include"`
(WHATWG WebSockets Standard), so cookies ride along on an upgrade started by *any* page, and there
is no CORS read barrier. Socket.IO's docs: "CORS only applies to HTTP long-polling. WebSocket
connections are not subject to CORS restrictions." PortSwigger defines cross-site WebSocket
hijacking as "a cross-site request forgery (CSRF) vulnerability on a WebSocket handshake," present
when the handshake "relies solely on HTTP cookies for session handling"; unlike ordinary CSRF the
attacker gets "two-way interaction," reading every message pushed to the victim. RFC 6455 §10.2:
servers that serve only certain sites "SHOULD verify the |Origin| field is an origin they expect"
and reject with 403.

**SameSite helps but is not the control.** OWASP recommends `SameSite=Lax` or `Strict`, and Lax
only sends cookies cross-site on top-level `GET` navigations. But SameSite is about *site*: "a
cross-origin request can still be same-site" (PortSwigger). A Discord-OAuth session cookie scoped
to `.example.com` is same-site for `app.`, `status.`, a docs host and any user-content subdomain,
so XSS on any sibling host is a same-site CSWSH. Only an exact-match origin allowlist separates
them.

```ts
// BAD — cookie alone authenticates; any page on the internet can open this socket as the victim
const wss = new WebSocketServer({ server });          // handshake auto-accepted
wss.on('connection', async (ws, req) => {
  const session = await sessionFromCookie(req.headers.cookie);
  if (session) subscribeToCommunity(ws, session);
});
// BAD — origin.endsWith('example.com') passes attacker-example.com; includes() passes app.example.com.evil.net
```

```ts
// GOOD — exact allowlist, checked in the 'upgrade' handler before handleUpgrade (ws)
import { STATUS_CODES, type IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer } from 'ws';

const ALLOWED_ORIGINS = new Set(['https://app.example.com', 'https://admin.example.com']);
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

function reject(socket: Duplex, status: 400 | 401 | 403 | 429 | 500) {
  socket.end(`HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\nConnection: close\r\n\r\n`);
}

server.on('upgrade', async (req: IncomingMessage, socket: Duplex, head: Buffer) => {
  socket.on('error', () => socket.destroy());
  try {
    const origin = req.headers.origin;                 // browsers always send Origin on a WebSocket handshake
    if (!origin || !ALLOWED_ORIGINS.has(origin)) return reject(socket, 403);
    const session = await sessionFromCookie(req.headers.cookie);
    if (!session) return reject(socket, 401);
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, session));
  } catch {
    reject(socket, 500);                               // an async listener's rejection would crash Node
  }
});
```

Browsers attach `Origin` to every WebSocket handshake and every CORS request (Fetch Standard), so a
handshake *without* one is a non-browser client. Requiring it on a cookie-authenticated WebSocket
route costs browser users nothing. A route for non-browser clients (a game server's API key in a
header, a ticket from §2) may skip the Origin check — but must then **ignore cookies entirely**.

## 2. Handshake Authentication: Tokens in the URL vs Single-Use Tickets

**What to look for:** a JWT, API key, or session id in a `new WebSocket(...)`/`new EventSource(...)`
URL or in Socket.IO's `query` option; a long-lived bearer token minted just to put in a URL.

**Why it's exploitable:** the browser APIs leave no header slot. `EventSource` takes a URL and one
option, `withCredentials` (WHATWG HTML); Socket.IO's client docs note "the WebSocket API in the
browser does not allow providing custom headers." So the token goes in the query string, and OWASP
is direct: "Avoid tokens in URL query strings because they can leak into access logs" — the
proxy's, the CDN's, the APM agent's. (Referer is not the main leak: the WebSocket request's referrer
is `"no-referrer"` per the WebSockets Standard; it becomes one only if the token is also in the page
URL.) A long-lived token in a log is a session anyone with log access can replay.

**Fix — mint a short-lived, single-use ticket through an authenticated POST:**

```ts
// GOOD — Hono: cookie-authenticated, Origin-checked POST mints a 30-second, one-time ticket
import { randomBytes, createHash } from 'node:crypto';
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

app.post('/realtime/tickets', requireOrigin, requireSession, async (c) => {
  const { communityId } = TicketRequest.parse(await c.req.json());
  const s = c.get('session');
  if (!(await canViewCommunity(s.userId, communityId))) return c.json({ error: 'forbidden' }, 403);
  const ticket = randomBytes(32).toString('base64url');
  await db.insert(realtimeTickets).values({
    hash: sha256(ticket), userId: s.userId, sessionId: s.id, communityId,
    expiresAt: new Date(Date.now() + 30_000),
  });
  return c.json({ ticket });
});

// Redeem in the 'upgrade' handler, AFTER §1's Origin check — atomically single-use
async function redeemTicket(ticket: string) {
  const [row] = await db.delete(realtimeTickets)
    .where(and(eq(realtimeTickets.hash, sha256(ticket)), gt(realtimeTickets.expiresAt, new Date())))
    .returning();
  return row ?? null;   // userId, sessionId, communityId: the connection's identity and scope
}
```

A logged ticket is worthless after use or after 30 s. Redemption does not re-check that the session
is still alive; a session revoked inside that 30-second window is caught by §4, because the
connection inherits `sessionId`. The upgrade still runs §1's Origin check before redeeming, so a
ticket leaked to another site can't be used from a browser there. Two other sound designs: send the
token as the **first message** over `wss://` (OWASP: "accept only the authentication message and do
not send protected data" until it validates; close on timeout), or Socket.IO's `auth` option, which
travels in the namespace `CONNECT` packet's payload rather than the URL.

**`EventSource` reconnects with the same URL** (the spec re-fetches the original request, adding
only `Last-Event-ID`). The consumed ticket then fails, and any non-200 response "fail[s] the
connection" — the browser stops retrying. On `error` with `readyState === EventSource.CLOSED`, mint
a fresh ticket and open a new `EventSource`. For a same-site stream, the session cookie (with
`withCredentials: true` when cross-origin, §10) is simpler.

## 3. Where the Check Must Run: ws, Socket.IO, Hono, Next.js Custom Servers

- **ws.** `verifyClient` exists but "Use of `verifyClient` is discouraged. Rather handle client
  authentication in the `'upgrade'` event of the HTTP server." With `noServer: true`, your
  `'upgrade'` handler calls `wss.handleUpgrade(request, socket, head, cb)` only after the checks
  pass (§1). Without either, "the handshake is automatically accepted."
- **Socket.IO.** `cors` covers long-polling only. `allowRequest` receives "a given handshake or
  upgrade request" — the Origin allowlist goes there. Identity goes in `io.use((socket, next) => …)`,
  run once per connection; `next(new Error(...))` refuses it. `io.use` is `io.of('/').use` — **main
  namespace only**; `io.of('/admin')` needs its own `.use`. A regex namespace like `io.of(/^\/\w+$/)`
  "allows any client to create a new namespace by connecting to a matching name"; use the function
  form `io.of((name, auth, next) => …)` to authorize creation per tenant.
  `connectionStateRecovery.skipMiddlewares: true` skips middleware on recovery, which "might, for
  example, allow users blocked during the disconnection period to reconnect."
- **Hono.** `upgradeWebSocket` is an ordinary route handler: on `@hono/node-server` v2 (and the
  deprecated `@hono/node-ws`) the upgrade request goes through the Hono app, so route middleware
  runs first and a non-upgrade response's status is written back. Put Origin + session middleware
  *on the route*. Hono's `csrf()` does **not** cover it — it validates only "unsafe HTTP methods
  (not GET, HEAD, or OPTIONS)," and an upgrade is a `GET`. Hono also warns that header-modifying
  middleware such as CORS on a WebSocket route can fail with immutable-header errors.
- **Next.js custom server.** With an `'upgrade'` listener registered, Node emits upgrades there
  instead of the `'request'` flow — `handle(req, res)`, `proxy.ts` (formerly `middleware.ts`), and
  route-handler auth never see them. The `'upgrade'` handler must do the session lookup itself.

```ts
// GOOD — Hono on @hono/node-server v2: checks run as middleware before the upgrade
import { serve, upgradeWebSocket } from '@hono/node-server';
import { createMiddleware } from 'hono/factory';
import { WebSocketServer } from 'ws';

const requireOrigin = createMiddleware(async (c, next) => {
  const origin = c.req.header('origin');
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return c.text('Forbidden', 403);
  await next();
});

app.get('/ws', requireOrigin, requireSession, upgradeWebSocket((c) => {
  const session = c.get('session');             // identity from the verified session, never from a frame
  return { onMessage: (evt, ws) => handleFrame(session, evt.data, ws) };
}));

const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });   // you own the options here
serve({ fetch: app.fetch, websocket: { server: wss } });
```

```ts
// GOOD — Socket.IO: origin in allowRequest, identity in io.use, per-namespace middleware
const io = new Server(httpServer, {
  cors: { origin: [...ALLOWED_ORIGINS], credentials: true },             // long-polling only
  allowRequest: (req, cb) => {
    const origin = req.headers.origin;
    // A same-origin polling GET carries no Origin (Fetch Standard); a WebSocket upgrade or a
    // cross-origin request from a browser always does. Missing Origin = same-origin or non-browser.
    cb(null, origin === undefined || ALLOWED_ORIGINS.has(origin));
  },
  maxHttpBufferSize: 64 * 1024,
});
const authenticate = async (socket: Socket, next: (err?: Error) => void) => {
  const session = await sessionFromCookie(socket.request.headers.cookie).catch(() => null);
  if (!session) return next(new Error('unauthorized'));                  // generic message, §11
  socket.data.session = session;
  next();
};
io.use(authenticate);
io.of('/admin').use(authenticate).use(requireStaffRole);                 // io.use does not cover /admin
io.on('connection', (socket) => socket.join(`session:${socket.data.session.id}`));   // revocation handle, §4
```

## 4. Connections That Outlive the Session

**What to look for:** identity read once at connect and cached forever; logout, revocation, ban,
kick, or role change that updates the database but never touches open connections; revocation
held in one instance's memory; a revoked game-server API key whose socket keeps streaming.

**Why it's exploitable:** the handshake was the only check. OWASP: "When users log out, close all
their WebSocket connections immediately," "Close WebSocket connections when sessions expire," and
"Re-validate user sessions periodically (every 30 minutes is common)." A demoted moderator keeps
receiving staff-only events; a stolen session revoked from the account page keeps working on the
socket that stole it.

**Fix:** index connections by session, close them on a revocation event delivered to *every*
instance, and re-validate on a timer as the backstop.

```ts
// GOOD — event-driven close plus a periodic re-check (ws)
const bySession = new Map<string, Set<WebSocket>>();

wss.on('connection', (ws, _req, session) => {
  const set = bySession.get(session.id) ?? new Set();
  bySession.set(session.id, set.add(ws));
  ws.on('close', () => set.delete(ws));
});

bus.subscribe('session.revoked', ({ sessionId }) => closeSession(sessionId));   // logout/ban/role change

function closeSession(sessionId: string) {
  for (const ws of bySession.get(sessionId) ?? []) ws.close(1008, 'session ended');
  bySession.delete(sessionId);
}

setInterval(async () => {
  const live = await validSessionIds([...bySession.keys()]).catch(() => null);   // one batched query
  if (live) for (const id of bySession.keys()) if (!live.has(id)) closeSession(id);
}, 60_000);
```

- **Socket.IO:** each socket joined `session:<id>` (§3), so `io.in(\`session:${id}\`).disconnectSockets(true)`
  closes them; the docs note these utility methods work across servers with the Redis adapter.
- **Role change:** re-run §5's check for every room the user is in and leave the ones they lost.
- **SSE:** end the stream (`stream.close()` in Hono) and answer the reconnect with `204` ("a client
  can be told to stop reconnecting using the HTTP 204 No Content response code") or `401`. Long-poll
  re-authenticates on every poll, as long as the check is on the poll route.

## 5. Channel, Room, and Subscription Authorization

**What to look for:** a `subscribe`/`join` handler that joins whatever community, channel, or room
id the client sent; room names concatenated from client strings; `GET /communities/:id/events`
that checks the session but not membership of `:id`.

**Why it's exploitable:** this is IDOR with a push channel attached. Rooms "are a **server-only**
concept (i.e. the client does not have access to the list of rooms it has joined)," and only the
server calls `socket.join` — so a handler that joins whatever the client named hands that decision
to the client. A client sending `{ channel: 'community:7:staff' }` or `{ channel: 'user:123' }`
receives every event later emitted to that room.

```ts
// BAD — client chooses the room
socket.on('subscribe', ({ channel }) => socket.join(channel));
```

```ts
// GOOD — validate shape, authorize against current membership, build the room name server-side
const Subscribe = z.object({ communityId: z.string().uuid(), scope: z.enum(['public', 'staff']) });

socket.on('subscribe', async (raw, ack) => {
  try {
    const parsed = Subscribe.safeParse(raw);
    if (!parsed.success) return ack?.({ ok: false });
    const { communityId, scope } = parsed.data;
    const role = await roleInCommunity(socket.data.session.userId, communityId);   // fresh, not cached
    if (!role || (scope === 'staff' && !isStaff(role))) return ack?.({ ok: false });
    socket.join(`community:${communityId}:${scope}`);
    ack?.({ ok: true });
  } catch {
    ack?.({ ok: false });
  }
});
```

The same check applies to an SSE route (authorize `:id` on every connect and reconnect) and to a
long-poll route (on every poll). The general IDOR pattern is in `secaudit:web-vulns`.

## 6. Per-Message Authorization and Inbound Frame Validation

**What to look for:** `JSON.parse(data)` with no try/catch and no schema; a `switch (msg.type)`
that dispatches any action for any user; a `userId`, `communityId`, or `role` read from the frame
and trusted; actions authorized against the role captured at connect.

**Why it's exploitable:** an open socket is not a permission. OWASP: "Don't assume WebSocket
connection equals unlimited access. Check authorization for each action," and "Treat all WebSocket
messages as untrusted input." A frame is a request body with no route in front of it.

```ts
// GOOD — ws: size bounded by maxPayload; parse, validate, authorize per action; never reject unhandled
const Frame = z.discriminatedUnion('type', [
  z.object({ type: z.literal('chat.send'), communityId: z.string().uuid(), text: z.string().max(2000) }),
  z.object({ type: z.literal('player.kick'), communityId: z.string().uuid(), playerId: z.string() }),
]);

ws.on('message', (data, isBinary) => {
  handleFrame(session, data, isBinary, ws).catch(() => ws.close(1011, 'error'));
});

async function handleFrame(session: Session, data: RawData, isBinary: boolean, ws: WebSocket) {
  if (isBinary) return ws.close(1003, 'unsupported');
  let json: unknown;
  try { json = JSON.parse(data.toString()); } catch { return ws.close(1007, 'invalid'); }
  const msg = Frame.safeParse(json);
  if (!msg.success) return ws.send(JSON.stringify({ error: 'invalid_message' }));
  const role = await roleInCommunity(session.userId, msg.data.communityId);   // identity from the session
  if (!allowed(role, msg.data.type)) return ws.send(JSON.stringify({ error: 'forbidden' }));
  await handlers[msg.data.type](session, msg.data);
}
```

Socket.IO's per-packet middleware is `socket.use(([event, ...args], next) => …)`; call
`next(new Error(...))` on denial — one that calls neither `next()` nor `next(err)` silently drops
the packet. Message limits (OWASP: "100 messages per minute is a common starting point") are
designed in `secaudit:rate-limiting`.

## 7. Replay Cursors: `Last-Event-ID` and Long-Poll Positions

**What to look for:** `WHERE id > $lastEventId` with no tenant predicate; a cursor encoding a
community id that is then trusted as scope; unbounded replay; replay ignoring per-event visibility.

**Why it's exploitable:** on reconnect the browser sends the last `id:` it saw as `Last-Event-ID`,
but the header is a client-supplied string — the spec allows essentially any UTF-8 string without
NUL, LF, or CR. If events share a global sequence and replay filters by position alone, a client in
community A that sends `Last-Event-ID: 0` gets every tenant's history. Same for `?cursor=`.

```ts
// BAD — position is treated as scope
const rows = await db.select().from(events).where(gt(events.id, Number(lastEventId)));
```

```ts
// GOOD — the cursor is only a position; scope and visibility come from the authorized session
const after = /^\d{1,18}$/.test(lastEventId ?? '') ? BigInt(lastEventId!) : null;   // 18 digits < bigint max
const role = await roleInCommunity(session.userId, communityId);              // authorized in §5
const rows = await db.select().from(events).where(and(
  eq(events.communityId, communityId),
  inArray(events.visibility, visibleTo(role)),                                // current role, not role at write time
  after === null ? gt(events.createdAt, sinceReplayWindow()) : gt(events.id, after),
)).orderBy(events.id).limit(500);                                             // bounded replay
```

A signed cursor still needs scope re-derived from the route and session: the signature proves you
issued it, not that this user may still read that scope.

## 8. Fan-Out From a Shared Pub/Sub

**What to look for:** one `LISTEN` (or Redis `SUBSCRIBE`/`PSUBSCRIBE`) connection per process whose
handler writes every payload to *all* sockets; filtering done in the browser; a pattern
subscription like `community:*` forwarded without per-socket checks.

**Why it's exploitable:** the bus doesn't know who is on each socket. node-postgres delivers each
notification as `{ processId, channel, payload }`; a Redis pattern subscription delivers messages
from every channel whose name matches the pattern. Authorization has to happen in the loop that
writes to sockets, per subscriber, *before* the write.

```ts
// BAD — every connected client receives every tenant's event
pg.on('notification', (n) => { for (const ws of wss.clients) ws.send(n.payload!); });
```

```ts
// GOOD — route by tenant, check each subscriber's current visibility, then write
const byCommunity = new Map<string, Set<Conn>>();   // populated by §5's authorized subscribe

pg.on('notification', (n) => {
  const evt = EventEnvelope.safeParse(safeJson(n.payload));                 // { communityId, eventId, visibility, data }
  if (!evt.success) return;
  for (const conn of byCommunity.get(evt.data.communityId) ?? []) {
    if (conn.canSee(evt.data.visibility)) send(conn, evt.data);             // role kept current by §4; §9 backpressure
  }
});
```

For sensitive content, prefer payloads that carry ids and read the row through the same
tenant-scoped query the REST API uses. Who may `LISTEN`/`NOTIFY`, why payloads bypass row-level
security, and payload limits are Postgres-side questions — see `secaudit:postgres-security`.

## 9. Resource Limits and Denial of Service

**What to look for:** `ws` without `maxPayload`; Socket.IO `maxHttpBufferSize` raised; no per-user
or per-IP connection cap; no heartbeat; `send()` with no look at `bufferedAmount`; long-poll
requests held with no bound. Every open connection costs a socket, memory, often a timer and a bus
subscription — and the attacker pays almost nothing to hold one.

- **Message size.** `ws` `maxPayload` defaults to `104857600` (100 MiB); Socket.IO's
  `maxHttpBufferSize` defaults to `1e6` (1 MB) and "matches the maxPayload option of the ws
  package." OWASP suggests "typically 64KB or less." Current `ws` also caps `maxFragments` (default
  16384) and `maxBufferedChunks` (default 262144); `0` disables either. `@hono/node-ws` builds
  `new WebSocketServer({ noServer: true })` with no options, so it runs at the 100 MiB default; on
  `@hono/node-server` v2 you construct the server and pass `maxPayload` (§3).
- **Connection caps.** Count per user (OWASP's preference) and per IP at upgrade, *before*
  `handleUpgrade`, answer `429`, and share counters across instances (`secaudit:rate-limiting`).
  The IP is `req.socket.remoteAddress` unless a trusted proxy rewrites `X-Forwarded-For` — the
  `ws` README's FAQ takes the *leftmost* XFF entry, which the client controls (`secaudit:proxy-trust`). Socket.IO keeps regex-namespace children in memory
  after the last socket leaves unless `cleanupEmptyChildNamespaces` is set.
- **Heartbeats and idle timeouts.** Node's HTTP `server.timeout` defaults to `0` (no inactivity
  timeout), so the HTTP layer won't reap idle SSE or long-poll sockets. The `ws` README pings every
  30 s and `terminate()`s a socket that didn't pong; Socket.IO has `pingInterval` (25000),
  `pingTimeout` (20000), and `connectTimeout` (45000). Close first-message-auth sockets (§2) that
  haven't authenticated within seconds.
- **Backpressure.** `bufferedAmount` is bytes queued by `send()` but not yet transmitted; a client
  that stops reading grows it without bound. Check it before each write; `terminate()` past a limit.
- **Compression.** `permessage-deflate` is off by default on a `ws` server ("a significant overhead
  in terms of performance and memory consumption"); Socket.IO's `perMessageDeflate` defaults to
  `false`. Leave it off unless a measured need says otherwise.
- **Long-poll.** A held request is a connection by design: cap hold time below the proxy's read
  timeout (nginx `proxy_read_timeout` defaults to 60 s), allow one outstanding poll per session, and
  cap concurrent polls per user/IP.

```ts
// GOOD — per-user cap at upgrade, error listener, backpressure-aware send (ws)
const perUser = new Map<string, number>();
const MAX_PER_USER = 5, MAX_BUFFERED = 1 << 20;

// inside the 'upgrade' handler, after authentication:
if ((perUser.get(session.userId) ?? 0) >= MAX_PER_USER) return reject(socket, 429);

wss.on('connection', (ws, _req, session) => {
  perUser.set(session.userId, (perUser.get(session.userId) ?? 0) + 1);
  ws.on('error', () => ws.terminate());                                      // never leave 'error' unhandled
  ws.on('close', () => perUser.set(session.userId, perUser.get(session.userId)! - 1));
});

function send(ws: WebSocket, data: unknown) {
  if (ws.bufferedAmount > MAX_BUFFERED) return ws.terminate();               // slow consumer: drop, don't buffer
  ws.send(JSON.stringify(data));
}
```

## 10. SSE and Long-Poll Specifics

**Cross-origin `EventSource` is a CORS request** whose credentials mode follows `withCredentials`
(WHATWG HTML), so a cross-origin stream needs an exact `Access-Control-Allow-Origin` and, for
cookies, `Access-Control-Allow-Credentials: true`. Reflecting any origin with credentials lets any
site read the stream. Hono's CORS middleware did that when `credentials: true` was set and
`origin` left at its wildcard default — CVE-2026-54290 (GHSA-88fw-hqm2-52qc), fixed 4.12.25.

**GET must not change state.** CORS blocks *reading* a cross-origin response, not sending it: a
cross-site `EventSource` or long-poll `GET` still executes, and Hono's `csrf()` skips `GET` (§3).
No "mark delivered," no cursor advance on read, no job started by a poll; acknowledgements go over
a CSRF-protected `POST`.

**Event-field injection.** SSE delimits fields with newlines, so untrusted values in `event:` or
`id:` can inject fields. Hono's `writeSSE()` did not reject CR/LF in `event`, `id`, or `retry` —
CVE-2026-29085 (GHSA-p6xx-57qc-3wxr), fixed 4.12.4; current Hono throws on CR/LF in `event`/`id`
and emits one `data:` line per input line. Do the same in a hand-rolled writer, and render `e.data`
with `textContent`, never `innerHTML` (`secaudit:web-vulns`).

**Buffering proxies and compression.** nginx buffers proxied responses by default
(`proxy_buffering on`); buffering "can also be enabled or disabled by passing 'yes' or 'no' in the
'X-Accel-Buffering' response header field" (unless `proxy_ignore_headers` disables that), so send
`X-Accel-Buffering: no`. A buffered stream delays close and revocation events with everything
else. The WHATWG spec suggests a `:` comment line "every 15 seconds or so" for idle proxies. Hono's
`compress()` default filter excludes `text/event-stream`; a custom `contentTypeFilter` matching it,
or Express `compression()` without `res.flush()`, holds events in the compressor.

**Sticky sessions and multi-node.** Socket.IO across processes needs sticky sessions, disabled
long-polling, or client-side load balancing, plus an adapter. §4's revocation and §8's fan-out must
cross nodes through that adapter or bus; a local `Map` closes only the sockets on one node.

```ts
// GOOD — Hono SSE: authorized, read-only, unbuffered, heartbeat, generic error event
app.get('/communities/:id/stream', requireOrigin, requireSession, async (c) => {
  const communityId = c.req.param('id');
  const session = c.get('session');
  if (!(await canViewCommunity(session.userId, communityId))) return c.body(null, 403);
  c.header('X-Accel-Buffering', 'no');
  return streamSSE(c, async (stream) => {
    const unsubscribe = subscribe(communityId, session, (evt) => {
      stream.writeSSE({ event: 'update', id: String(evt.id), data: JSON.stringify(evt.data) })
        .catch(() => stream.abort());                                       // dead client: stop, don't throw
    });
    stream.onAbort(unsubscribe);
    try {
      while (!stream.aborted) { await stream.write(': ping\n\n'); await stream.sleep(15_000); }
    } catch (err) {
      log.error({ err, communityId }, 'sse stream failed');                 // detail to logs only
      await stream.writeSSE({ event: 'error', data: 'stream_error' }).catch(() => {});
    }
  });
});
```

## 11. Error and Close Messages

- **Socket.IO** delivers a middleware error's `message` — and any `err.data` — to the client's
  `connect_error` handler. A database error passed through tells the client your schema.
- **Hono `streamSSE`:** when the callback throws and an `onError` handler is passed, Hono awaits
  `onError` and then writes `event: error` with `data: e.message` to the stream (see the helper's
  source). Catch inside the callback and write a generic event, as in §10.
- **Close frames:** RFC 6455 code `1008` exists for when there "is a need to hide specific details
  about the policy." The browser API rejects reasons over 123 bytes; use a fixed vocabulary
  (`session ended`, `invalid`), never an exception string.
- **Unhandled `'error'` crashes the process.** Socket.IO's CVE-2024-38355 was a crafted packet
  triggering an unhandled `'error'` event; the `ws` README attaches `ws.on('error', …)` to every
  connection. The same goes for async listeners: a rejected promise from an `'upgrade'` or
  `'message'` handler is an unhandled rejection (§1, §6).

## 12. Known Advisories (2024–2026)

Check the lock file — `socket.io` pulls `engine.io` and `socket.io-parser` through `~` ranges that
resolve to whatever was pinned. Run `npm ls ws engine.io socket.io-parser socket.io
@socket.io/cluster-engine hono`. Clean floors (no open OSV advisory) include `ws@8.21.0`,
`engine.io@6.6.10`, and `socket.io-parser@4.2.7`; Hono floors are in `secaudit:framework-versions`.

- **ws CVE-2024-37890** (GHSA-3h5v-q93c-6h6q): too many headers crash the server. Fixed 8.17.1, 7.5.10, 6.2.3, 5.2.4.
- **ws CVE-2026-48779** (GHSA-96hv-2xvq-fx4p): tiny-fragment memory exhaustion. Fixed 8.21.0, 7.5.11, 6.2.4, 5.2.5.
- **ws CVE-2026-45736** (GHSA-58qx-3vcg-4xpx): `close()` with a `TypedArray` reason leaks memory. Fixed 8.20.1.
- **socket.io CVE-2024-38355** (GHSA-25hc-qcg6-38wj): unhandled `'error'` event kills the process. Fixed 4.6.2, 2.5.1.
- **socket.io-parser CVE-2026-33151** (GHSA-677m-j7p3-52f9): unbounded binary attachments. Fixed 4.2.6, 3.4.4, 3.3.5.
- **socket.io-parser CVE-2026-69185** (GHSA-2m8v-j782-fhvr): zero-attachment memory exhaustion. Fixed 4.2.7, 3.4.5, 3.3.6.
- **engine.io CVE-2026-59725** (GHSA-r635-g3xr-vw7x): bad polling `POST`s exhaust connections. Fixed 6.6.7.
- **engine.io CVE-2026-59724** (GHSA-gr94-w7qr-f4j3): `__proto__` session id crash, WebTransport only. Fixed 6.6.7.
- **engine.io CVE-2026-102599** (GHSA-2gc4-cqfq-p2gv): `EIO` revision mismatch on upgrade crashes. Fixed 6.6.10.
- **@socket.io/cluster-engine CVE-2026-102600** (GHSA-wfpm-5gcm-94cg): prototype-chain session lookup crash. Fixed 0.1.1.
- **hono CVE-2026-29085** (GHSA-p6xx-57qc-3wxr): `writeSSE()` CR/LF field injection (§10). Fixed 4.12.4.
- **hono CVE-2026-54290** (GHSA-88fw-hqm2-52qc): credentialed CORS reflects any origin (§10). Fixed 4.12.25.

## Realtime Footgun Checklist

- Cookie-authenticated WebSocket upgrade with no exact-match `Origin` allowlist, or
  `endsWith`/`includes`/unanchored-regex matching; a no-Origin route that still accepts cookies.
- Socket.IO `cors` as the WebSocket origin check (no `allowRequest`); `ws` `verifyClient` instead of
  `'upgrade'` + `handleUpgrade`; Hono `csrf()` assumed to cover a `GET`; a Next.js custom-server
  `'upgrade'` handler trusting `proxy.ts`.
- `io.use` auth with an unprotected `io.of('/admin')` or regex namespace; `skipMiddlewares: true`;
  a session, JWT, or API key in a WebSocket/`EventSource` URL instead of a single-use ticket.
- Logout, ban, role change, or key revocation that never closes open sockets on every node.
- `socket.join(clientSuppliedName)`; subscribe/message/replay checks using the role from connect
  time or a `userId`/`role` from the frame.
- `Last-Event-ID`/cursor replay without tenant predicate, visibility filter, or bound; fan-out that
  writes every payload to every socket.
- `ws` at the 100 MiB `maxPayload` default (every `@hono/node-ws` server); no connection cap,
  heartbeat, `bufferedAmount` check, or long-poll hold limit.
- SSE without `X-Accel-Buffering: no` or compressed; a state-changing SSE/long-poll `GET`;
  credentialed CORS with a reflected origin; untrusted `event:`/`id:`; `e.data` via `innerHTML`.
- Exception text in `connect_error`, close reasons, or `streamSSE`'s `onError` path; a socket with
  no `'error'` listener; an async listener that can reject; a lock file below §12's fixed versions.

## Related skills

- `secaudit:proxy-trust` — which client IP a per-IP cap can key on; leftmost `X-Forwarded-For` (§9).
- `secaudit:rate-limiting` — per-message/per-connection limit design and shared counters (§6, §9).
- `secaudit:auth` — session cookie attributes (`SameSite`, `Domain` across hosts) and the session
  store and revocation §4 hooks into.
- `secaudit:postgres-security` — LISTEN/NOTIFY internals: who may `LISTEN`/`NOTIFY`, RLS bypass,
  payload limits, poolers breaking `LISTEN` (§8).
- `secaudit:web-vulns` — IDOR (§5) and XSS from rendering streamed data (§10).
- `secaudit:data-access` — schema validation of untrusted input, per frame (§6).
- `secaudit:logging-monitoring` — what belongs in logs versus error responses (§11).
- `secaudit:framework-versions` — current clean Hono and Next.js floors (§12).

## Sources

- https://www.rfc-editor.org/rfc/rfc6455.html -- §10.2 servers SHOULD verify `Origin` and reply 403; close codes 1003/1007/1008/1011, 1008 for hiding policy details
- https://websockets.spec.whatwg.org/ -- WebSocket request credentials mode "include", referrer "no-referrer"; `close()` reason over 123 bytes throws
- https://fetch.spec.whatwg.org/ -- `Origin` appended for CORS-tainted and "websocket"-mode requests, not same-origin GET/HEAD
- https://html.spec.whatwg.org/multipage/server-sent-events.html -- `EventSource(url, { withCredentials })`; potential-CORS request; non-200 fails the connection; 204 stops reconnection; `Last-Event-ID` on reconnect and its value space; 15-second comment heartbeat
- https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html -- Origin allowlist, no tokens in URLs, first-message auth, SameSite, per-action authorization, close on logout/expiry, 30-minute re-validation, 64KB, 100 msg/min, per-user connection limits
- https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking -- CSWSH definition, cookie-only handshake condition, two-way interaction
- https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions -- site vs origin, Lax top-level-GET rule, CSWSH via sibling domains
- https://github.com/websockets/ws/blob/master/doc/ws.md -- `maxPayload` 104857600, `maxFragments` 16384, `maxBufferedChunks` 262144, `verifyClient` discouraged, `noServer`, `handleUpgrade`, auto-accept, server `perMessageDeflate` off, `isBinary`, `bufferedAmount`, `terminate()`
- https://github.com/websockets/ws/blob/master/README.md -- `'upgrade'` + `handleUpgrade` auth example, heartbeat, permessage-deflate overhead, leftmost `X-Forwarded-For` FAQ example, per-connection `'error'` listeners
- https://socket.io/docs/v4/handling-cors/ -- "CORS only applies to HTTP long-polling"; `allowRequest` to restrict
- https://socket.io/docs/v4/server-options/ -- `allowRequest`, `maxHttpBufferSize` 1e6, `pingInterval` 25000, `pingTimeout` 20000, `connectTimeout` 45000, `perMessageDeflate` false, `skipMiddlewares` warning
- https://socket.io/docs/v4/middlewares/ -- `io.use` once per connection; `next(err)` message and `data` reach `connect_error`; socket not yet connected in middleware
- https://socket.io/docs/v4/namespaces/ -- `io.use` is `io.of("/").use`; per-namespace middleware; regex namespace warning; function form; `cleanupEmptyChildNamespaces`
- https://socket.io/docs/v4/rooms/ -- rooms are a server-only concept
- https://socket.io/docs/v4/server-socket-instance/ -- `socket.use` per-packet middleware; dropped packets without `next`; `socket.data`
- https://socket.io/docs/v4/server-instance/ -- `disconnectSockets`; utility methods across servers with the Redis adapter
- https://socket.io/docs/v4/client-options/ -- `auth`, `query`, `extraHeaders` ignored by the browser WebSocket API
- https://socket.io/docs/v4/using-multiple-nodes/ -- sticky sessions, disabling long-polling, adapters
- https://github.com/socketio/socket.io-protocol -- `CONNECT` packet carries the auth payload
- https://hono.dev/docs/helpers/websocket -- `upgradeWebSocket`, Node via `@hono/node-server` + `WebSocketServer({ noServer: true })`, `@hono/node-ws` deprecated, CORS immutable-header warning
- https://github.com/honojs/node-server -- `serve({ fetch, websocket: { server: wss } })`
- https://github.com/honojs/middleware/blob/main/packages/node-ws/src/index.ts -- `new WebSocketServer({ noServer: true })` with no options; upgrade routed through the Hono app first
- https://hono.dev/docs/helpers/streaming -- `streamSSE`, `writeSSE`, `stream.aborted`, `onAbort`
- https://github.com/honojs/hono/blob/main/src/helper/streaming/sse.ts -- CR/LF rejection in `event`/`id`; per-line `data:`; `onError` then `event: error` with `e.message`
- https://hono.dev/docs/middleware/builtin/csrf -- `csrf()` skips GET/HEAD/OPTIONS
- https://github.com/honojs/hono/blob/main/src/utils/compress.ts -- default compressible regex excludes `text/event-stream`
- https://github.com/expressjs/compression -- SSE needs `res.flush()`
- https://nginx.org/en/docs/http/ngx_http_proxy_module.html -- `proxy_buffering on`, `X-Accel-Buffering`, `proxy_ignore_headers`, `proxy_read_timeout` 60s
- https://nodejs.org/api/http.html -- `'upgrade'` replaces the `'request'` flow; `server.timeout` default 0; `maxHeadersCount`
- https://nextjs.org/docs/app/guides/custom-server -- custom server `handle(req, res)`
- https://nextjs.org/docs/app/api-reference/file-conventions/proxy -- `middleware` renamed to `proxy`
- https://node-postgres.com/apis/client -- `notification` event `{ processId, channel, payload }`
- https://redis.io/docs/latest/develop/pubsub/ -- `PSUBSCRIBE` matches channel names against a pattern
- https://github.com/advisories/GHSA-3h5v-q93c-6h6q -- ws CVE-2024-37890; fixed 8.17.1 / 7.5.10 / 6.2.3 / 5.2.4
- https://github.com/advisories/GHSA-96hv-2xvq-fx4p -- ws CVE-2026-48779; fixed 8.21.0 / 7.5.11 / 6.2.4 / 5.2.5
- https://github.com/advisories/GHSA-58qx-3vcg-4xpx -- ws CVE-2026-45736; fixed 8.20.1
- https://github.com/advisories/GHSA-25hc-qcg6-38wj -- socket.io CVE-2024-38355; fixed 4.6.2 / 2.5.1
- https://github.com/advisories/GHSA-677m-j7p3-52f9 -- socket.io-parser CVE-2026-33151; fixed 4.2.6 / 3.4.4 / 3.3.5
- https://github.com/advisories/GHSA-2m8v-j782-fhvr -- socket.io-parser CVE-2026-69185; fixed 4.2.7 / 3.4.5 / 3.3.6
- https://github.com/advisories/GHSA-r635-g3xr-vw7x -- engine.io CVE-2026-59725; fixed 6.6.7
- https://github.com/advisories/GHSA-gr94-w7qr-f4j3 -- engine.io CVE-2026-59724; fixed 6.6.7
- https://github.com/advisories/GHSA-2gc4-cqfq-p2gv -- engine.io CVE-2026-102599; fixed 6.6.10
- https://github.com/advisories/GHSA-wfpm-5gcm-94cg -- @socket.io/cluster-engine CVE-2026-102600; fixed 0.1.1
- https://github.com/advisories/GHSA-p6xx-57qc-3wxr -- hono CVE-2026-29085; fixed 4.12.4
- https://github.com/advisories/GHSA-88fw-hqm2-52qc -- hono CVE-2026-54290; fixed 4.12.25
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025: CSWSH, room IDOR, cross-tenant fan-out and replay
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ -- A07:2025: URL tokens, connections outliving the session
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ -- A02:2025: permissive origin/CORS, default limits
- https://top10.owasp.org/2025/A06_2025-Insecure_Design/ -- A06:2025: missing per-connection resource model
- https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/ -- A10:2025: unhandled socket errors, streamed exception text
