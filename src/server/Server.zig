// Copyright (C) 2023-2025 Lightpanda (Selecy SAS)
//
// Francis Bouvier <francis@lightpanda.io>
// Pierre Tachoire <pierre@lightpanda.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const lp = @import("lightpanda");
const builtin = @import("builtin");

const App = @import("../App.zig");
const Config = @import("../Config.zig");
const sys_net = @import("../sys/net.zig");

const CDP = @import("cdp/CDP.zig");
const BiDi = @import("bidi/BiDi.zig");
const Handshake = @import("Handshake.zig");
const Driver = @import("Driver.zig");

const log = lp.log;
const posix = std.posix;
const Allocator = std.mem.Allocator;

const Server = @This();

app: *App,
max_connections: usize,
json_version_response: []const u8,

driver_mutex: std.Io.Mutex = .init,
drivers: std.ArrayList(Driver) = .empty,

// Number of active conns, used to enforce the cdp-max-connections limit.
active_conns: std.atomic.Value(u32) = .init(0),
// Number of existing threads, used to deinit correctly.
// It can be higher than active_conns b/c we free conn slots early.
active_threads: std.atomic.Value(u32) = .init(0),

cdp_pool: std.heap.MemoryPool(CDP),

pub fn init(app: *App, address: sys_net.IpAddress) !*Server {
    const self = try app.allocator.create(Server);
    errdefer app.allocator.destroy(self);

    self.* = .{
        .app = app,
        .cdp_pool = .empty,
        .json_version_response = "",
        .max_connections = app.config.maxConnections(),
    };
    errdefer self.cdp_pool.deinit(app.allocator);

    // Bind first so /json/version can advertise the OS-assigned port (--port 0).
    var bound_address = address;
    try app.network.bind(&bound_address, self, onAccept);
    log.note(.app, "server running", .{ .address = bound_address });

    self.json_version_response = try buildJSONVersionResponse(app, bound_address.getPort());
    return self;
}

pub fn shutdown(self: *Server) void {
    self.driver_mutex.lockUncancelable(lp.io);
    defer self.driver_mutex.unlock(lp.io);

    self.app.network.unbind();

    for (self.drivers.items) |*driver| {
        driver.shutdown();
    }
}

pub fn deinit(self: *Server) void {
    self.shutdown();

    while (self.active_threads.load(.monotonic) > 0) {
        lp.io.sleep(.fromMilliseconds(10), .awake) catch {};
    }

    const allocator = self.app.allocator;
    self.drivers.deinit(allocator);
    self.cdp_pool.deinit(allocator);
    self.app.allocator.free(self.json_version_response);
    self.app.allocator.destroy(self);
}

fn onAccept(ctx: *anyopaque, socket: posix.socket_t) void {
    const self: *Server = @ptrCast(@alignCast(ctx));

    configureSocket(socket) catch {
        _ = std.c.close(socket);
        return;
    };

    self.spawnWorker(socket) catch |err| {
        log.err(.app, "CDP spawn", .{ .err = err });
        _ = std.c.close(socket);
    };
}

// Liveness is enforced at the TCP layer via keepalive probes sent by the
// kernel. This is transparent to CDP clients — unlike a WebSocket ping, which
// go-rod panics on and chromedp logs as "malformed". Tunables in Config.zig.
fn configureSocket(socket: posix.socket_t) !void {
    posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(c_int, 1))) catch |err| {
        log.warn(.app, "SO_KEEPALIVE", .{ .err = err });
        return err;
    };

    const idle_opt = switch (builtin.os.tag) {
        .macos, .ios => posix.TCP.KEEPALIVE,
        else => posix.TCP.KEEPIDLE,
    };
    posix.setsockopt(socket, posix.IPPROTO.TCP, idle_opt, &std.mem.toBytes(Config.CDP_KEEPALIVE_IDLE_S)) catch |err| {
        log.warn(.app, "TCP_KEEPIDLE", .{ .err = err });
        return err;
    };
    posix.setsockopt(socket, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, &std.mem.toBytes(Config.CDP_KEEPALIVE_INTVL_S)) catch |err| {
        log.warn(.app, "TCP_KEEPINTVL", .{ .err = err });
        return err;
    };
    posix.setsockopt(socket, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, &std.mem.toBytes(Config.CDP_KEEPALIVE_CNT)) catch |err| {
        log.warn(.app, "TCP_KEEPCNT", .{ .err = err });
        return err;
    };

    if (builtin.os.tag == .linux) {
        posix.setsockopt(socket, posix.IPPROTO.TCP, std.os.linux.TCP.USER_TIMEOUT, &std.mem.toBytes(Config.CDP_TCP_USER_TIMEOUT_MS)) catch |err| {
            log.warn(.app, "TCP_USER_TIMEOUT", .{ .err = err });
            return err;
        };
    }
}

fn spawnWorker(self: *Server, socket: posix.socket_t) !void {
    if (self.app.shutdown()) {
        return error.ShuttingDown;
    }

    // Atomically increment active_conns only if below max_connections.
    // Uses CAS loop to avoid race between checking the limit and incrementing.
    //
    // cmpxchgWeak may fail for two reasons:
    // 1. Another thread changed the value (increment or decrement)
    // 2. Spurious failure on some architectures (e.g. ARM)
    //
    // We use Weak instead of Strong because we need a retry loop anyway:
    // if CAS fails because a conn slot was freed (counter decreased), we should
    // retry rather than return an error - there may now be room for a new connection.
    //
    // On failure, cmpxchgWeak returns the actual value, which we reuse to avoid
    // an extra load on the next iteration.
    var current = self.active_conns.load(.monotonic);
    while (current < self.max_connections) {
        current = self.active_conns.cmpxchgWeak(current, current + 1, .monotonic, .monotonic) orelse break;
    } else {
        lp.metrics.serve_connection_limit.incr();
        return error.MaxConnectionsReached;
    }
    errdefer _ = self.active_conns.fetchSub(1, .monotonic);

    _ = self.active_threads.fetchAdd(1, .monotonic);
    errdefer _ = self.active_threads.fetchSub(1, .monotonic);

    const thread = try std.Thread.spawn(.{}, handleConnection, .{ self, socket });
    thread.detach();
}

fn handleConnection(self: *Server, socket: posix.socket_t) void {
    var active_conns_early_release = false;
    defer {
        if (!active_conns_early_release) {
            _ = self.active_conns.fetchSub(1, .monotonic);
        }
    }
    defer _ = self.active_threads.fetchSub(1, .monotonic);
    defer _ = std.c.close(socket);

    const route = Handshake.run(self.app, socket, self.json_version_response) orelse return;
    switch (route) {
        .cdp => self.serveCDP(socket, &active_conns_early_release),
        .bidi => self.serveBiDi(socket, &active_conns_early_release),
    }
}

// The socket is an upgraded websocket speaking CDP.
fn serveCDP(self: *Server, socket: posix.socket_t, active_conns_early_release: *bool) void {
    const cdp = blk: {
        const allocator = self.app.allocator;
        self.driver_mutex.lockUncancelable(lp.io);
        defer self.driver_mutex.unlock(lp.io);
        break :blk self.cdp_pool.create(allocator) catch @panic("OOM");
    };
    defer {
        self.driver_mutex.lockUncancelable(lp.io);
        defer self.driver_mutex.unlock(lp.io);
        self.cdp_pool.destroy(cdp);
    }

    cdp.init(self.app, socket) catch |err| {
        log.err(.app, "CDP init", .{ .err = err });
        return;
    };
    defer cdp.deinit();

    lp.metrics.serve_connections.incr(.cdp);
    lp.metrics.serve_active_connections.incr(.cdp);
    defer lp.metrics.serve_active_connections.decr(.cdp);

    self.serve(.init(.{ .cdp = cdp }), active_conns_early_release);
}

// The socket is an upgraded websocket speaking WebDriver BiDi.
fn serveBiDi(self: *Server, socket: posix.socket_t, active_conns_early_release: *bool) void {
    const allocator = self.app.allocator;

    // heap-allocated: BiDi embeds a Browser
    const bidi = allocator.create(BiDi) catch @panic("OOM");
    defer allocator.destroy(bidi);

    bidi.init(self.app, socket) catch |err| {
        log.err(.app, "BiDi init", .{ .err = err });
        return;
    };
    defer bidi.deinit();

    lp.metrics.serve_connections.incr(.bidi);
    lp.metrics.serve_active_connections.incr(.bidi);
    defer lp.metrics.serve_active_connections.decr(.bidi);

    self.serve(.init(.{ .bidi = bidi }), active_conns_early_release);
}

// Everything a live connection needs regardless of which protocol it
// speaks: tracking (so shutdown can reach it), handing the read side to
// the Network thread, and running the worker loop.
fn serve(self: *Server, driver: Driver, active_conns_early_release: *bool) void {
    const conn = driver.conn;

    if (log.enabled(.app, .info)) {
        const client_address = getClientAddress(conn.socket) catch null;
        log.info(.app, "client connected", .{ .ip = client_address });
    }

    self.track(driver);
    defer self.untrack(driver);

    {
        // Transition from .starting state to .live
        // Lock needed even though the main thread hasn't seen this yet because
        // shutdown could access this from the sighandler thread.
        self.driver_mutex.lockUncancelable(lp.io);
        defer self.driver_mutex.unlock(lp.io);
        conn.state = .live;
    }

    // Hand the read side of the socket over to the Network thread.
    // From here until the matching unregisterClient, the worker must NOT
    // read from the socket directly — bytes arrive via the inbox.
    // unregisterClient is synchronous, so by the time it returns Network
    // is guaranteed to be done with this link.
    //
    // driver_link_active gates HttpClient.perform's block in
    // curl_multi_poll: with it false (tests, pre-handshake), perform
    // skips the poll when there's no in-flight curl work — sleeping
    // would just eat the timeout waiting for a wakeup that won't
    // come. We set it true *after* registerClient so Network is already
    // accepting wakeups by the time the worker might poll, and clear
    // it *after* unregisterClient returns (Network is guaranteed done
    // with us by then).
    self.app.network.registerClient(driver.link);
    driver.browser.http_client.driver_link_active = true;
    defer {
        self.app.network.unregisterClient(driver.link);
        driver.browser.http_client.driver_link_active = false;
    }

    // Check shutdown after markLive so that a concurrent shutdown either
    // sees us as .live and terminates us, or we observe the stop signal
    // here. Otherwise we could miss it and block deinit() indefinitely.
    if (self.app.shutdown()) {
        return;
    }

    driver.run();

    // Try to release the connection as soon as possible: the browser/V8
    // teardown in our callers' defers can take milliseconds, and a client
    // that disconnects and immediately reconnects shouldn't be rejected
    // for a slot we're merely unwinding.
    active_conns_early_release.* = true;
    _ = self.active_conns.fetchSub(1, .monotonic);
}

fn track(self: *Server, driver: Driver) void {
    self.driver_mutex.lockUncancelable(lp.io);
    defer self.driver_mutex.unlock(lp.io);
    self.drivers.append(self.app.allocator, driver) catch {};
}

fn untrack(self: *Server, driver: Driver) void {
    self.driver_mutex.lockUncancelable(lp.io);
    defer self.driver_mutex.unlock(lp.io);

    for (self.drivers.items, 0..) |*d, i| {
        if (d.conn == driver.conn) {
            _ = self.drivers.swapRemove(i);
            break;
        }
    }
}

fn getClientAddress(socket: posix.socket_t) !sys_net.IpAddress {
    var storage: posix.sockaddr.storage = undefined;
    var socklen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try posix.getpeername(socket, @ptrCast(&storage), &socklen);
    return sys_net.addressFromSockaddr(@ptrCast(&storage));
}

// The pointed-to driver is owned by its worker thread
fn buildJSONVersionResponse(app: *const App, port: u16) ![]const u8 {
    const host = app.config.advertiseHost();
    if (app.config.bindIsWildcard()) {
        // Serve is bound to INADDR_ANY but no --advertise-host was given;
        // advertiseHost() falls back to 127.0.0.1 so clients can still
        // connect locally. Surface the trade-off so users running
        // outside the same host know they have to opt in.
        log.note(.cdp, "advertising loopback for wildcard bind", .{
            .message = "--host is a wildcard (0.0.0.0 / ::) without --advertise-host; clients on other hosts will need --advertise-host to reach the CDP endpoint",
        });
    }
    const body_format =
        "{{" ++
        "\"Browser\": \"Lightpanda/1.0\", " ++
        "\"Protocol-Version\": \"1.3\", " ++
        "\"User-Agent\": \"Lightpanda/1.0\", " ++
        "\"Lightpanda-Version\": \"" ++ lp.build_config.version ++ "\", " ++
        "\"webSocketDebuggerUrl\": \"ws://{s}:{d}/\"" ++
        "}}";
    const body_len = std.fmt.count(body_format, .{ host, port });

    // We send a Connection: Close (and actually close the connection)
    // because chromedp (Go driver) sends a request to /json/version and then
    // does an upgrade request, on a different connection. Since we only allow
    // 1 connection at a time, the upgrade connection doesn't proceed until we
    // timeout the /json/version. So, instead of waiting for that, we just
    // always close HTTP requests.
    const response_format =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Connection: Close\r\n" ++
        "Content-Type: application/json; charset=UTF-8\r\n\r\n" ++
        body_format;
    return try std.fmt.allocPrint(app.allocator, response_format, .{ body_len, host, port });
}

const testing = @import("../testing.zig");
test "server: buildJSONVersionResponse" {
    const res = try buildJSONVersionResponse(testing.test_app, testing.test_app.config.port());
    defer testing.test_app.allocator.free(res);

    // The response includes the build version, so check structure rather than exact bytes.
    try testing.expect(std.mem.startsWith(u8, res, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, res, "Content-Type: application/json") != null);
    try testing.expect(std.mem.indexOf(u8, res, "Connection: Close") != null);

    // Verify all required JSON fields are present in the body
    try testing.expect(std.mem.indexOf(u8, res, "\"Browser\": \"Lightpanda/") != null);
    try testing.expect(std.mem.indexOf(u8, res, "\"Protocol-Version\": \"1.3\"") != null);
    try testing.expect(std.mem.indexOf(u8, res, "\"User-Agent\": \"Lightpanda/") != null);
    try testing.expect(std.mem.indexOf(u8, res, "\"Lightpanda-Version\": \"" ++ lp.build_config.version ++ "\"") != null);
    try testing.expect(std.mem.indexOf(u8, res, "\"webSocketDebuggerUrl\": \"ws://127.0.0.1:9222/\"") != null);
}

test "Client: http invalid request" {
    testing.silenceLog(&.{.cdp});

    var c = try createTestClient();
    defer c.deinit();

    const res = try c.httpRequest("GET /over/9000 HTTP/1.1\r\n" ++ "Header: " ++ ("a" ** 4100) ++ "\r\n\r\n");
    try testing.expectEqual("HTTP/1.1 413 \r\n" ++
        "Connection: Close\r\n" ++
        "Content-Length: 17\r\n\r\n" ++
        "Request too large", res);
}

test "Client: http invalid handshake" {
    try assertHTTPError(
        400,
        "Invalid request",
        "\r\n\r\n",
    );

    try assertHTTPError(
        404,
        "Not found",
        "GET /over/9000 HTTP/1.1\r\n\r\n",
    );

    try assertHTTPError(
        404,
        "Not found",
        "POST / HTTP/1.1\r\n\r\n",
    );

    try assertHTTPError(
        400,
        "Invalid HTTP protocol",
        "GET / HTTP/1.0\r\n\r\n",
    );

    try assertHTTPError(
        400,
        "Missing required header",
        "GET / HTTP/1.1\r\n\r\n",
    );

    try assertHTTPError(
        400,
        "Missing required header",
        "GET / HTTP/1.1\r\nConnection:  upgrade\r\n\r\n",
    );

    try assertHTTPError(
        400,
        "Missing required header",
        "GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
    );

    try assertHTTPError(
        400,
        "Missing required header",
        "GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version:13\r\n\r\n",
    );
}

test "Client: http handshake origin" {
    testing.silenceLog(&.{.cdp});

    const with_origin =
        "GET / HTTP/1.1\r\n" ++
        "Connection: upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "sec-websocket-version:13\r\n" ++
        "sec-websocket-key: this is my key\r\n" ++
        "Origin: {s}\r\n\r\n";

    for ([_][]const u8{
        "https://evil.com",
        // Being served from loopback yourself doesn't make you trusted.
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        // Sandboxed iframes and data: URLs.
        "null",
    }) |origin| {
        var c = try createTestClient();
        defer c.deinit();

        var buf: [256]u8 = undefined;
        const res = try c.httpRequest(try std.fmt.bufPrint(&buf, with_origin, .{origin}));
        try testing.expectEqual("HTTP/1.1 403 \r\n" ++
            "Connection: Close\r\n" ++
            "Content-Length: 18\r\n\r\n" ++
            "Origin not allowed", res);
    }

    // The first one is enough; we never get far enough to see the second.
    try assertHTTPError(
        403,
        "Origin not allowed",
        "GET / HTTP/1.1\r\n" ++
            "Connection: upgrade\r\n" ++
            "Upgrade: websocket\r\n" ++
            "sec-websocket-version:13\r\n" ++
            "sec-websocket-key: this is my key\r\n" ++
            "Origin: https://evil.com\r\n" ++
            "Origin: https://evil.com\r\n\r\n",
    );
}

test "Client: http handshake host" {
    testing.silenceLog(&.{.cdp});

    // Any name in Host means something resolved to us that shouldn't
    // have (rebinding); only an IP literal gets through.
    const with_host =
        "GET / HTTP/1.1\r\n" ++
        "Connection: upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "sec-websocket-version:13\r\n" ++
        "sec-websocket-key: this is my key\r\n" ++
        "Host: {s}\r\n\r\n";

    for ([_][]const u8{
        "rebind.evil.com:9583",
        // Not even the name that resolves to loopback on every machine.
        "localhost:9583",
    }) |host| {
        var buf: [256]u8 = undefined;
        try assertHTTPError(
            403,
            "Host not allowed",
            try std.fmt.bufPrint(&buf, with_host, .{host}),
        );
    }
}

test "Client: http valid handshake" {
    var c = try createTestClient();
    defer c.deinit();

    // No Origin (i.e. not a browser) and a Host we're reachable at: what
    // every CDP driver sends.
    const request =
        "GET /   HTTP/1.1\r\n" ++
        "Host: 127.0.0.1:9583\r\n" ++
        "Connection: upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "sec-websocket-version:13\r\n" ++
        "sec-websocket-key: this is my key\r\n" ++
        "Custom:  Header-Value\r\n\r\n";

    const res = try c.httpRequest(request);
    try testing.expectEqual("HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: upgrade\r\n" ++
        "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n\r\n", res);
}

test "Client: read invalid websocket message" {
    // 131 = 128 (fin) | 3  where 3 isn't a valid type
    try assertWebSocketError(
        1002,
        &.{ 131, 128, 'm', 'a', 's', 'k' },
    );

    for ([_]u8{ 16, 32, 64 }) |rsv| {
        // none of the reserve flags should be set
        try assertWebSocketError(
            1002,
            &.{ rsv, 128, 'm', 'a', 's', 'k' },
        );

        // as a bitmask
        try assertWebSocketError(
            1002,
            &.{ rsv + 4, 128, 'm', 'a', 's', 'k' },
        );
    }

    // client->server messages must be masked
    try assertWebSocketError(
        1002,
        &.{ 129, 1, 'a' },
    );

    // control types (ping/ping/close) can't be > 125 bytes
    for ([_]u8{ 136, 137, 138 }) |op| {
        try assertWebSocketError(
            1002,
            &.{ op, 254, 1, 1 },
        );
    }

    {
        testing.expectLog(&.{.cdp});
        // length of message is 0, 0, 0, 0, 0, 16, 0, 1 i.e: 1024 * 1024 + 1
        try assertWebSocketError(1009, &.{ 129, 255, 0, 0, 0, 0, 0, 16, 0, 1, 'm', 'a', 's', 'k' });
    }

    // continuation type message must come after a normal message
    // even when not a fin frame
    try assertWebSocketError(
        1002,
        &.{ 0, 129, 'm', 'a', 's', 'k', 'd' },
    );

    // continuation type message must come after a normal message
    // even as a fin frame
    try assertWebSocketError(
        1002,
        &.{ 128, 129, 'm', 'a', 's', 'k', 'd' },
    );

    // text (non-fin) - text (non-fin)
    try assertWebSocketError(
        1002,
        &.{ 1, 129, 'm', 'a', 's', 'k', 'd', 1, 128, 'k', 's', 'a', 'm' },
    );

    // text (non-fin) - text (fin) should always been continuation after non-fin
    try assertWebSocketError(
        1002,
        &.{ 1, 129, 'm', 'a', 's', 'k', 'd', 129, 128, 'k', 's', 'a', 'm' },
    );

    // close must be fin
    try assertWebSocketError(
        1002,
        &.{
            8, 129, 'm', 'a', 's', 'k', 'd',
        },
    );

    // ping must be fin
    try assertWebSocketError(
        1002,
        &.{
            9, 129, 'm', 'a', 's', 'k', 'd',
        },
    );

    // pong must be fin
    try assertWebSocketError(
        1002,
        &.{
            10, 129, 'm', 'a', 's', 'k', 'd',
        },
    );
}

test "Client: ping reply" {
    try assertWebSocketMessage(
        // fin | pong, len
        &.{ 138, 0 },

        // fin | ping, masked | len, 4-byte mask
        &.{ 137, 128, 0, 0, 0, 0 },
    );

    try assertWebSocketMessage(
        // fin | pong, len, payload
        &.{ 138, 5, 100, 96, 97, 109, 104 },

        // fin | ping, masked | len, 4-byte mask, 5 byte payload
        &.{ 137, 133, 0, 5, 7, 10, 100, 101, 102, 103, 104 },
    );
}

test "Client: close message" {
    try assertWebSocketMessage(
        // fin | close, len, close code (normal)
        &.{ 136, 2, 3, 232 },

        // fin | close, masked | len, 4-byte mask
        &.{ 136, 128, 0, 0, 0, 0 },
    );
}

test "server: bidi session lifecycle" {
    var c = try createTestClient();
    defer c.deinit();
    try c.handshake("/session");

    try c.bidiCommand("{\"id\":1,\"method\":\"session.status\"}");
    try assertBidiMessage(&c, .{ .type = "success", .id = 1, .result = .{ .ready = true, .message = "" } });

    // capture the sessionId from session.new by hand — it's random
    try c.bidiCommand("{\"id\":2,\"method\":\"session.new\",\"params\":{\"capabilities\":{}}}");
    {
        const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
        defer if (msg.cleanup_fragment) c.reader.cleanup();

        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, msg.data, .{});
        defer parsed.deinit();

        const obj = parsed.value.object;
        try testing.expectEqual("success", obj.get("type").?.string);
        try testing.expectEqual(2, obj.get("id").?.integer);

        const result = obj.get("result").?.object;
        try testing.expectEqual(36, result.get("sessionId").?.string.len);

        const capabilities = result.get("capabilities").?.object;
        try testing.expectEqual("Lightpanda", capabilities.get("browserName").?.string);
        try testing.expectEqual(lp.build_config.version, capabilities.get("browserVersion").?.string);
        try testing.expectEqual(false, capabilities.get("acceptInsecureCerts").?.bool);
    }

    try c.bidiCommand("{\"id\":3,\"method\":\"session.status\"}");
    try assertBidiMessage(&c, .{ .type = "success", .id = 3, .result = .{ .ready = false, .message = "session already started" } });

    try c.bidiCommand("{\"id\":4,\"method\":\"session.new\"}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 4, .@"error" = "session not created", .message = "session already exists" });

    try c.bidiCommand("{\"id\":5,\"method\":\"session.subscribe\",\"params\":{\"events\":[\"log.entryAdded\"]}}");
    {
        // the subscription id is random
        const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
        defer if (msg.cleanup_fragment) c.reader.cleanup();

        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, msg.data, .{});
        defer parsed.deinit();
        try testing.expectEqual("success", parsed.value.object.get("type").?.string);
        try testing.expectEqual(36, parsed.value.object.get("result").?.object.get("subscription").?.string.len);
    }

    try c.bidiCommand("{\"id\":6,\"method\":\"session.unsubscribe\",\"params\":{\"events\":[\"log.entryAdded\"]}}");
    // an empty result must serialize as {}, not [] — struct {}{} on the
    // expected side asserts the object-ness
    try assertBidiMessage(&c, .{ .type = "success", .id = 6, .result = struct {}{} });

    try c.bidiCommand("{\"id\":7,\"method\":\"session.end\"}");
    try assertBidiMessage(&c, .{ .type = "success", .id = 7, .result = struct {}{} });

    // ending the session closes the connection
    {
        const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
        defer if (msg.cleanup_fragment) c.reader.cleanup();
        try testing.expectEqual(.close, msg.type);
    }
}

test "server: bidi errors" {
    var c = try createTestClient();
    defer c.deinit();
    try c.handshake("/session");

    try c.bidiCommand("this is not json");
    try assertBidiMessage(&c, .{ .type = "error", .id = null, .@"error" = "invalid argument", .message = "invalid JSON message" });

    try c.bidiCommand("{\"method\":\"session.status\"}");
    try assertBidiMessage(&c, .{ .type = "error", .id = null, .@"error" = "invalid argument", .message = "missing command id" });

    try c.bidiCommand("{\"id\":1}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 1, .@"error" = "invalid argument", .message = "missing command method" });

    try c.bidiCommand("{\"id\":2,\"method\":\"browsingContext.getTree\"}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 2, .@"error" = "invalid session id", .message = "no active session" });

    // session-scoped commands before session.new
    try c.bidiCommand("{\"id\":3,\"method\":\"session.subscribe\"}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 3, .@"error" = "invalid session id", .message = "no active session" });

    try c.bidiCommand("{\"id\":4,\"method\":\"session.end\"}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 4, .@"error" = "invalid session id", .message = "no active session" });

    // an unknown command is reported as such even before session.new; only
    // known commands in known modules reach the session gate
    try c.bidiCommand("{\"id\":5,\"method\":\"session.over9000\"}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 5, .@"error" = "unknown command", .message = "session.over9000" });

    try c.bidiCommand("{\"id\":6,\"method\":\"storage.getCookies\"}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 6, .@"error" = "unknown command", .message = "storage.getCookies" });

    try c.bidiCommand("{\"id\":7,\"method\":\"nodothere\"}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 7, .@"error" = "unknown command", .message = "nodothere" });
}

test "server: bidi browsingContext" {
    var c = try createTestClient();
    defer c.deinit();
    try c.handshake("/session");

    try c.bidiCommand("{\"id\":1,\"method\":\"session.new\",\"params\":{\"capabilities\":{}}}");
    try discardBidiMessage(&c); // response shape covered by the lifecycle test

    var context_id: [36]u8 = undefined;
    try c.bidiCommand("{\"id\":2,\"method\":\"browsingContext.create\",\"params\":{\"type\":\"tab\"}}");
    {
        const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
        defer if (msg.cleanup_fragment) c.reader.cleanup();

        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, msg.data, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try testing.expectEqual("success", obj.get("type").?.string);
        const context = obj.get("result").?.object.get("context").?.string;
        try testing.expectEqual(36, context.len);
        @memcpy(&context_id, context);
    }

    try c.bidiCommand("{\"id\":3,\"method\":\"browsingContext.getTree\"}");
    try assertBidiMessage(&c, .{ .type = "success", .id = 3, .result = .{ .contexts = .{.{
        .context = &context_id,
        .url = "about:blank",
        .userContext = "default",
        .originalOpener = null,
        .children = .{},
    }} } });

    try c.bidiCommand("{\"id\":4,\"method\":\"session.subscribe\",\"params\":{\"events\":[\"browsingContext.domContentLoaded\",\"browsingContext.load\"]}}");
    try discardBidiMessage(&c);

    const url = "http://127.0.0.1:9582/src/browser/tests/cdp/dom2.html";
    var buf: [256]u8 = undefined;
    try c.bidiCommand(try std.fmt.bufPrint(
        &buf,
        "{{\"id\":5,\"method\":\"browsingContext.navigate\",\"params\":{{\"context\":\"{s}\",\"url\":\"" ++ url ++ "\",\"wait\":\"complete\"}}}}",
        .{&context_id},
    ));
    try assertBidiEvent(&c, "browsingContext.domContentLoaded", &context_id, url);
    try assertBidiEvent(&c, "browsingContext.load", &context_id, url);
    {
        const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
        defer if (msg.cleanup_fragment) c.reader.cleanup();

        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, msg.data, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try testing.expectEqual("success", obj.get("type").?.string);
        try testing.expectEqual(5, obj.get("id").?.integer);
        const result = obj.get("result").?.object;
        try testing.expectEqual(url, result.get("url").?.string);
        try testing.expectEqual(36, result.get("navigation").?.string.len);
    }

    try c.bidiCommand("{\"id\":6,\"method\":\"browsingContext.navigate\",\"params\":{\"context\":\"00000000-0000-0000-0000-000000000000\",\"url\":\"about:blank\"}}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 6, .@"error" = "no such frame", .message = "unknown context" });

    try c.bidiCommand("{\"id\":7,\"method\":\"browsingContext.create\",\"params\":{\"type\":\"tab\"}}");
    try assertBidiMessage(&c, .{ .type = "error", .id = 7, .@"error" = "unsupported operation" });

    try c.bidiCommand(try std.fmt.bufPrint(
        &buf,
        "{{\"id\":8,\"method\":\"browsingContext.close\",\"params\":{{\"context\":\"{s}\"}}}}",
        .{&context_id},
    ));
    try assertBidiMessage(&c, .{ .type = "success", .id = 8, .result = struct {}{} });

    try c.bidiCommand("{\"id\":9,\"method\":\"browsingContext.getTree\"}");
    try assertBidiMessage(&c, .{ .type = "success", .id = 9, .result = .{ .contexts = .{} } });
}

fn discardBidiMessage(c: *TestClient) !void {
    const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
    if (msg.cleanup_fragment) {
        c.reader.cleanup();
    }
}

fn assertBidiEvent(c: *TestClient, method: []const u8, context: []const u8, url: []const u8) !void {
    const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
    defer if (msg.cleanup_fragment) {
        c.reader.cleanup();
    };

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, msg.data, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqual("event", obj.get("type").?.string);
    try testing.expectEqual(method, obj.get("method").?.string);

    const p = obj.get("params").?.object;
    try testing.expectEqual(context, p.get("context").?.string);
    try testing.expectEqual(url, p.get("url").?.string);
    try testing.expectEqual(36, p.get("navigation").?.string.len);
}

fn assertBidiMessage(c: *TestClient, expected: anytype) !void {
    const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
    defer if (msg.cleanup_fragment) {
        c.reader.cleanup();
    };

    try testing.expectEqual(.text, msg.type);
    try testing.expectJson(expected, msg.data);
}

test "server: 404" {
    var c = try createTestClient();
    defer c.deinit();

    const res = try c.httpRequest("GET /unknown HTTP/1.1\r\n\r\n");
    try testing.expectEqual("HTTP/1.1 404 \r\n" ++
        "Connection: Close\r\n" ++
        "Content-Length: 9\r\n\r\n" ++
        "Not found", res);
}

test "server: get /json/version" {
    {
        // twice on the same connection
        var c = try createTestClient();
        defer c.deinit();

        const res1 = try c.httpRequest("GET /json/version HTTP/1.1\r\n\r\n");
        try testing.expect(std.mem.startsWith(u8, res1, "HTTP/1.1 200 OK\r\n"));
        try testing.expect(std.mem.indexOf(u8, res1, "\"Browser\": \"Lightpanda/") != null);
        try testing.expect(std.mem.indexOf(u8, res1, "\"Protocol-Version\": \"1.3\"") != null);
        try testing.expect(std.mem.indexOf(u8, res1, "\"webSocketDebuggerUrl\": \"ws://127.0.0.1:9583/\"") != null);
    }

    {
        // again on a new connection
        var c = try createTestClient();
        defer c.deinit();

        const res1 = try c.httpRequest("GET /json/version HTTP/1.1\r\n\r\n");
        try testing.expect(std.mem.startsWith(u8, res1, "HTTP/1.1 200 OK\r\n"));
        try testing.expect(std.mem.indexOf(u8, res1, "\"Browser\": \"Lightpanda/") != null);
    }
}

test "server: get /json/protocol" {
    var c = try createTestClient();
    defer c.deinit();

    const res = try c.httpRequestAlloc("GET /json/protocol HTTP/1.1\r\n\r\n");
    defer testing.allocator.free(res);

    try testing.expect(std.mem.startsWith(u8, res, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, res, "Content-Type: application/json") != null);

    const body_start = std.mem.indexOf(u8, res, "\r\n\r\n").? + 4;
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, res[body_start..], .{});
    defer parsed.deinit();

    const domains = parsed.value.object.get("domains").?.array;
    try testing.expectEqual(20, domains.items.len);

    var found_dom = false;
    var found_lp = false;
    for (domains.items) |domain| {
        const name = domain.object.get("domain").?.string;
        if (std.mem.eql(u8, name, "DOM")) found_dom = true;
        if (std.mem.eql(u8, name, "LP")) found_lp = true;
    }
    try testing.expect(found_dom);
    try testing.expect(found_lp);
}

test "server: get /metrics" {
    var c = try createTestClient();
    defer c.deinit();

    const res = try c.httpRequest("GET /metrics HTTP/1.1\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, res, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, res, "Content-Type: text/plain; version=0.0.4") != null);
    try testing.expect(std.mem.indexOf(u8, res, "build_info{version=") != null);
    try testing.expect(std.mem.indexOf(u8, res, "# TYPE serve_connections_total counter") != null);
}

fn assertHTTPError(
    comptime expected_status: u16,
    comptime expected_body: []const u8,
    input: []const u8,
) !void {
    var c = try createTestClient();
    defer c.deinit();

    const res = try c.httpRequest(input);
    const expected_response = std.fmt.comptimePrint(
        "HTTP/1.1 {d} \r\nConnection: Close\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ expected_status, expected_body.len, expected_body },
    );

    try testing.expectEqual(expected_response, res);
}

fn assertWebSocketError(close_code: u16, input: []const u8) !void {
    var c = try createTestClient();
    defer c.deinit();

    try c.handshake("/");
    try sys_net.writeAll(c.socket, input);

    const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
    defer if (msg.cleanup_fragment) {
        c.reader.cleanup();
    };

    try testing.expectEqual(.close, msg.type);
    try testing.expectEqual(2, msg.data.len);
    try testing.expectEqual(close_code, std.mem.readInt(u16, msg.data[0..2], .big));
}

fn assertWebSocketMessage(expected: []const u8, input: []const u8) !void {
    var c = try createTestClient();
    defer c.deinit();

    try c.handshake("/");
    try sys_net.writeAll(c.socket, input);

    const msg = try c.readWebsocketMessage() orelse return error.NoMessage;
    defer if (msg.cleanup_fragment) {
        c.reader.cleanup();
    };

    const actual = c.reader.buf[0 .. msg.data.len + 2];
    try testing.expectEqualSlices(u8, expected, actual);
}

const MockCDP = struct {
    messages: std.ArrayList([]const u8) = .empty,

    allocator: Allocator = testing.allocator,

    fn init(_: Allocator, client: anytype) MockCDP {
        _ = client;
        return .{};
    }

    fn deinit(self: *MockCDP) void {
        const allocator = self.allocator;
        for (self.messages.items) |msg| {
            allocator.free(msg);
        }
        self.messages.deinit(allocator);
    }

    fn handleMessage(self: *MockCDP, message: []const u8) bool {
        const owned = self.allocator.dupe(u8, message) catch unreachable;
        self.messages.append(self.allocator, owned) catch unreachable;
        return true;
    }
};

fn createTestClient() !TestClient {
    const address: sys_net.IpAddress = .{ .ip4 = .loopback(9583) };
    const socket = try sys_net.connect(&address);

    const timeout = std.mem.toBytes(posix.timeval{
        .sec = 10,
        .usec = 0,
    });
    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &timeout);
    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &timeout);
    return .{
        .socket = socket,
        .reader = .{
            .max_message_size = 1024,
            .allocator = testing.allocator,
            .buf = try testing.allocator.alloc(u8, 1024 * 16),
        },
    };
}

const TestClient = struct {
    socket: posix.socket_t,
    buf: [8192]u8 = undefined,
    reader: WS.Reader(false),

    const WS = @import("../network/WS.zig");

    fn deinit(self: *TestClient) void {
        _ = std.c.close(self.socket);
        self.reader.deinit();
    }

    fn httpRequest(self: *TestClient, req: []const u8) ![]const u8 {
        try sys_net.writeAll(self.socket, req);

        var pos: usize = 0;
        var total_length: ?usize = null;
        while (true) {
            const n = try posix.read(self.socket, self.buf[pos..]);
            if (n == 0) {
                return if (pos == self.buf.len) error.MessageTooLarge else error.NoMoreData;
            }
            pos += n;
            const response = self.buf[0..pos];
            if (total_length == null) {
                const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse continue;
                const header = response[0 .. header_end + 4];

                const cl = blk: {
                    const cl_header = "Content-Length: ";
                    const start = (std.mem.indexOf(u8, header, cl_header) orelse {
                        break :blk 0;
                    }) + cl_header.len;

                    const end = std.mem.indexOfScalarPos(u8, header, start, '\r') orelse {
                        return error.InvalidContentLength;
                    };

                    break :blk std.fmt.parseInt(usize, header[start..end], 10) catch {
                        return error.InvalidContentLength;
                    };
                };

                total_length = cl + header.len;
            }

            if (total_length) |tl| {
                if (pos == tl) {
                    return response;
                }
                if (pos > tl) {
                    return error.DataExceedsContentLength;
                }
            }
        }
    }

    // Reads until the server closes the connection, for responses larger
    // than buf (e.g. /json/protocol).
    fn httpRequestAlloc(self: *TestClient, req: []const u8) ![]const u8 {
        try sys_net.writeAll(self.socket, req);

        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(testing.allocator);
        while (true) {
            const n = try posix.read(self.socket, &self.buf);
            if (n == 0) {
                return response.toOwnedSlice(testing.allocator);
            }
            try response.appendSlice(testing.allocator, self.buf[0..n]);
        }
    }

    fn handshake(self: *TestClient, comptime path: []const u8) !void {
        const request =
            "GET " ++ path ++ "   HTTP/1.1\r\n" ++
            "Connection: upgrade\r\n" ++
            "Upgrade: websocket\r\n" ++
            "sec-websocket-version:13\r\n" ++
            "sec-websocket-key: this is my key\r\n" ++
            "Custom:  Header-Value\r\n\r\n";

        const res = try self.httpRequest(request);
        try testing.expectEqual("HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n\r\n", res);
    }

    // client->server frames must be masked; a zero mask leaves the payload
    // bytes unchanged.
    fn bidiCommand(self: *TestClient, payload: []const u8) !void {
        var frame: [1024]u8 = undefined;
        frame[0] = 129; // fin | text
        var header_len: usize = 2;
        if (payload.len <= 125) {
            frame[1] = 128 | @as(u8, @intCast(payload.len));
        } else {
            frame[1] = 128 | 126;
            std.mem.writeInt(u16, frame[2..4], @intCast(payload.len), .big);
            header_len = 4;
        }
        @memset(frame[header_len..][0..4], 0);
        @memcpy(frame[header_len + 4 ..][0..payload.len], payload);
        try sys_net.writeAll(self.socket, frame[0 .. header_len + 4 + payload.len]);
    }

    fn readWebsocketMessage(self: *TestClient) !?WS.Message {
        while (true) {
            // two frames can arrive in one read; drain buffered ones first
            if (try self.reader.next()) |msg| {
                return msg;
            }
            const n = try posix.read(self.socket, self.reader.readBuf());
            if (n == 0) {
                return error.Closed;
            }
            self.reader.len += n;
        }
    }
};
