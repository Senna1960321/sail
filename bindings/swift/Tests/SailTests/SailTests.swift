// The Swift package against libsail: real instances, through Swift only.

import Foundation
import XCTest
@testable import Sail

/// A free TCP port on loopback.
func freePort() -> UInt16 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    addr.sin_port = 0
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            _ = bind(fd, $0, len)
            _ = getsockname(fd, $0, &len)
        }
    }
    return UInt16(bigEndian: addr.sin_port)
}

/// A loopback server answering each connection with `answer` (what it
/// read when nil: an echo), on a thread of its own.
func serve(answer: [UInt8]? = nil) -> UInt16 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    var yes: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            _ = bind(fd, $0, len)
            _ = getsockname(fd, $0, &len)
        }
    }
    listen(fd, 16)
    Thread.detachNewThread {
        while true {
            let client = accept(fd, nil, nil)
            if client < 0 { return }
            Thread.detachNewThread {
                var buf = [UInt8](repeating: 0, count: 1024)
                let n = read(client, &buf, buf.count)
                if n > 0 {
                    let out = answer ?? Array(buf[0..<n])
                    _ = out.withUnsafeBytes { write(client, $0.baseAddress, out.count) }
                }
                close(client)
            }
        }
    }
    return UInt16(bigEndian: addr.sin_port)
}

/// Sends "ping" through the SOCKS inbound at `port` to an echo server;
/// whether it came back.
func echoThroughSocks(_ port: UInt16) -> Bool {
    let echo = serve()
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    defer { close(fd) }
    var timeout = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    addr.sin_port = port.bigEndian
    let connected = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else { return false }
    func send(_ bytes: [UInt8]) { _ = bytes.withUnsafeBytes { write(fd, $0.baseAddress, bytes.count) } }
    func receive(_ count: Int) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, count - got) }
            if n <= 0 { return nil }
            got += n
        }
        return buf
    }
    send([5, 1, 0])
    guard receive(2) != nil else { return false }
    send([5, 1, 0, 1, 127, 0, 0, 1, UInt8(echo >> 8), UInt8(echo & 0xff)])
    guard let reply = receive(10), reply[1] == 0 else { return false }
    send(Array("ping".utf8))
    return receive(4) == Array("ping".utf8)
}

func config(port: UInt16) -> String {
    """
    {
      "log": { "level": "info" },
      "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": \(port) }],
      "outbounds": [
        { "type": "selector", "tag": "sel", "outbounds": ["a", "b"] },
        { "type": "direct", "tag": "a" },
        { "type": "direct", "tag": "b" }
      ],
      "route": { "final": "sel" }
    }
    """
}

/// The first element of `stream` that `test` takes, within 10 s.
func first<T>(_ stream: AsyncThrowingStream<T, Error>, where test: @escaping (T) -> Bool) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            for try await value in stream where test(value) { return value }
            throw SailError(code: SailError.io, message: "the stream ended")
        }
        group.addTask {
            try await Task.sleep(nanoseconds: 10_000_000_000)
            throw SailError(code: SailError.timeout, message: "no such event")
        }
        let value = try await group.next()!
        group.cancelAll()
        return value
    }
}

/// Counts its own going: what the platform's closures hold.
final class Tracked: @unchecked Sendable {
    static let lock = NSLock()
    static var gone = 0
    deinit {
        Tracked.lock.lock()
        Tracked.gone += 1
        Tracked.lock.unlock()
    }
}

final class SailTests: XCTestCase {
    func testConnectionRecordParentIsOptionalWithinItsRun() throws {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("../../../../sail/src/control/json_snapshot.json")
        let snapshot = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
        var record = snapshot["connection_record"] as! [String: Any]
        record.removeValue(forKey: "parent_id")
        func read() throws -> ConnectionRecord {
            try decoder.decode(ConnectionRecord.self, from: JSONSerialization.data(withJSONObject: record))
        }
        let legacy = try read()
        XCTAssertNil(legacy.parentId)
        record["parent_id"] = NSNull()
        XCTAssertNil(try read().parentId)
        record["parent_id"] = UInt64(6)
        let attempt = try read()
        XCTAssertEqual(attempt.parentId, 6)
        XCTAssertEqual(attempt.id, legacy.id)
        XCTAssertEqual(attempt.runMs, legacy.runMs)
    }

    func testCapabilities() throws {
        let capabilities = try Sail.capabilities()
        XCTAssertFalse(capabilities.version.isEmpty)
        XCTAssertTrue(capabilities.features.contains("inbound-socks"))
    }

    /// The models read every field of the JSON sail publishes
    /// (sail/src/control/json_snapshot.json, which sail's own test pins):
    /// each key of it is a property of the model it decodes into, so a field
    /// sail adds or renames that a model does not follow fails here.
    func testTheModelsReadEveryFieldSailPublishes() throws {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("../../../../sail/src/control/json_snapshot.json")
        let snapshot = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
        func check<T: Decodable>(_ type: T.Type, _ key: String) throws {
            let data = try JSONSerialization.data(withJSONObject: snapshot[key]!)
            let value = try decoder.decode(type, from: data)
            everyKey(snapshot[key]!, isIn: value, at: key)
        }
        let models: [String: () throws -> Void] = [
            "capabilities": { try check(InstanceCapabilities.self, "capabilities") },
            "sail_capabilities": { try check(Capabilities.self, "sail_capabilities") },
            "connection": { try check(Connection.self, "connection") },
            "log": { try check(Log.self, "log") },
            "mode": { try check(Mode.self, "mode") },
            "outbound": { try check(Outbound.self, "outbound") },
            "providers": { try check(Providers.self, "providers") },
            "rule_sets": { try check(RuleSets.self, "rule_sets") },
            "state": { try check(State.self, "state") },
            "stop_report": { try check(StopReport.self, "stop_report") },
            "fault": { try check(Fault.self, "fault") },
            "reload_report": { try check(ReloadReport.self, "reload_report") },
            "routed": { try check(Routed.self, "routed") },
            "connection_record": { try check(ConnectionRecord.self, "connection_record") },
            "dns_exchange": { try check(DnsExchange.self, "dns_exchange") },
            "group_switch": { try check(GroupSwitch.self, "group_switch") },
            "dial_failed": { try check(DialFailed.self, "dial_failed") },
            "user_event": { try check(UserEvent.self, "user_event") },
            "system_change": { try check(SystemChange.self, "system_change") },
            "status": { try check(Status.self, "status") },
            "traffic": { try check(Traffic.self, "traffic") },
        ]
        // What the management API answers with, or an event read as text.
        let notModelled: Set<String> = ["network", "users", "stats", "inbounds", "inbound_users"]
        for key in snapshot.keys where !notModelled.contains(key) {
            guard let model = models[key] else {
                XCTFail("the snapshot's \(key) has no model here: add one, or say why not")
                continue
            }
            try model()
        }
    }

    /// What a newer sail adds, a field or a string value, does not fail.
    func testANewerSailsJsonStillReads() throws {
        let connection = try decode(Connection.self, """
        {"id": 1, "network": "sctp", "inbound_type": "a-new-kind", "inbound_tag": "in",
         "source": "127.0.0.1:1", "destination": "example.com:443", "upload": 0, "download": 0,
         "start": 0, "chains": [], "packages": [], "a_field_from_later": {"nested": [1, 2]}}
        """)
        XCTAssertEqual(connection.network, "sctp")
        let capabilities = try decode(InstanceCapabilities.self, """
        {"has_tun": false, "opens_tun": false, "protects_sockets": false, "needs_network": false, "has_modes": false}
        """)
        XCTAssertNil(capabilities.version, "a field an older sail lacks is nil")
    }

    func testAnInstanceIsDrivenFromSwift() async throws {
        let sail = try Sail(settings: "{\"log_lines\": 100}")
        XCTAssertEqual(try sail.state().state, "idle")
        XCTAssertThrowsError(try sail.traffic()) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.state)
        }
        let port = freePort()
        try sail.start(config: config(port: port))
        XCTAssertEqual(try sail.state().state, "running")
        XCTAssertThrowsError(try sail.start(config: "{}")) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.state)
        }
        XCTAssertTrue(echoThroughSocks(port))
        XCTAssertGreaterThanOrEqual(try sail.traffic().upTotal, 4)

        XCTAssertEqual(try sail.outbounds().map(\.tag), ["sel", "a", "b"])
        XCTAssertEqual(try sail.groups().first?.group?.selected, "a")
        try sail.select(group: "sel", member: "b")
        XCTAssertEqual(try sail.groups().first?.group?.selected, "b")
        XCTAssertThrowsError(try sail.select(group: "sel", member: "c")) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.invalidArgument)
        }
        XCTAssertEqual(try sail.mode(), Mode(mode: "Rule", modes: ["Rule"]))

        let url = "http://127.0.0.1:\(serve(answer: Array("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".utf8)))/"
        XCTAssertGreaterThanOrEqual(try sail.delay(tag: "a", url: url), 1)
        XCTAssertEqual(try sail.outbounds().first { $0.tag == "a" }?.history.count, 1)

        let logs = try await first(sail.logs(level: "info")) { $0.reset }
        XCTAssertFalse(logs.lines.isEmpty)

        XCTAssertNil(try sail.reloadReport(config: config(port: port)).recheck)
        let rechecked = try sail.reloadReport(config: config(port: port), recheckOpen: .closeRejected)
        XCTAssertEqual(rechecked.recheck, Recheck(closed: [], differ: []))

        try sail.stop()
        XCTAssertEqual(try sail.state().state, "stopped")
        try sail.start(config: config(port: port))
        XCTAssertTrue(echoThroughSocks(port))
        try sail.stop()
    }

    func testStatesAreFollowed() async throws {
        let sail = try Sail()
        let states = sail.states()
        try sail.start(config: config(port: freePort()))
        let running = try await first(states) { $0.state == "running" }
        XCTAssertNotNil(running.startedAtMs)
        try sail.stop()
    }

    func testAClientAnswersAsTheInstance() async throws {
        let path = "/tmp/sail-swift-\(getpid()).sock"
        let sail = try Sail()
        try sail.serve("{\"path\": \"\(path)\"}")
        let port = freePort()
        try sail.start(config: config(port: port))
        let client = try Sail.connect("{\"path\": \"\(path)\"}")
        XCTAssertEqual(try client.state().state, "running")
        XCTAssertEqual(try client.outbounds(), try sail.outbounds())
        try client.select(group: "sel", member: "b")
        XCTAssertEqual(try sail.groups().first?.group?.selected, "b")
        XCTAssertThrowsError(try client.start(config: "{}")) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.unsupported)
        }
        let statuses = client.statuses(intervalMs: 100)
        _ = try await first(statuses) { _ in true }
        // The service closes: the client's streams end, with the reason.
        let states = client.states()
        _ = try await first(states) { $0.state == "running" }
        try sail.serve(nil)
        do {
            for try await _ in states {}
            XCTFail("the stream did not fail")
        } catch let error as SailError {
            XCTAssertEqual(error.code, SailError.io)
        }
        try sail.stop()
    }

    func testThePlatformGoesWithTheInstance() throws {
        let before = Tracked.gone
        do {
            let tracked = Tracked()
            let sail = try Sail(platform: Platform(protectSocket: { _ in _ = tracked; return true }))
            let port = freePort()
            try sail.start(config: config(port: port))
            XCTAssertTrue(echoThroughSocks(port))
            try sail.stop()
        }
        // Freed with the instance, once it stopped.
        let deadline = Date().addingTimeInterval(10)
        while Tracked.gone == before && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        XCTAssertEqual(Tracked.gone, before + 1)
    }

    func testTheHostSaysWhichAppOpenedAConnection() throws {
        let asked = NSLock()
        var queries: [ConnectionQuery] = []
        let sail = try Sail(platform: Platform(findConnectionOwner: { query in
            asked.lock()
            queries.append(query)
            asked.unlock()
            return ConnectionOwner(uid: 10123, packages: ["com.blocked"])
        }))
        let port = freePort()
        try sail.start(config: """
        {
          "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": \(port) }],
          "outbounds": [{ "type": "direct" }],
          "route": { "rules": [{ "package_name": "com.blocked", "action": "reject" }] }
        }
        """)
        XCTAssertFalse(echoThroughSocks(port), "the app's connection was not rejected")
        asked.lock()
        XCTAssertEqual(queries.first?.network, "tcp")
        asked.unlock()
        try sail.stop()
    }

    func testProvidersAndRuleSetsAreToldAndUpdated() throws {
        let sail = try Sail()
        try sail.start(config: """
        {
          "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": \(freePort()) }],
          "outbounds": [{ "type": "selector", "tag": "g", "providers": "p" }, { "type": "direct", "tag": "direct" }],
          "outbound_providers": [{ "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "m1" }, { "type": "direct", "tag": "m2" }] }],
          "route": {
            "rule_set": [{ "type": "inline", "tag": "r", "rules": [{ "domain_suffix": ["a.example"] }] }],
            "rules": [{ "rule_set": "r", "outbound": "direct" }]
          }
        }
        """)
        let providers = try sail.providers()
        XCTAssertEqual(providers.first?.tag, "p")
        XCTAssertEqual(providers.first?.source, "inline")
        XCTAssertEqual(providers.first?.members, 2)
        try sail.updateProvider("p")
        XCTAssertThrowsError(try sail.updateProvider("nope")) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.notFound)
        }
        XCTAssertEqual(try sail.ruleSets().first?.tag, "r")
        try sail.updateRuleSet("r")
        try sail.stop()
    }

    func testADialGoesThroughTheOutboundNamed() throws {
        let sail = try Sail()
        try sail.start(config: config(port: freePort()))
        let echo = serve()
        let handle = try sail.dial(outbound: "a", network: .tcp, host: "127.0.0.1", port: echo)
        try handle.write(contentsOf: Data("ping".utf8))
        var back = Data()
        while back.count < 4, let more = try handle.read(upToCount: 4 - back.count), !more.isEmpty {
            back.append(more)
        }
        XCTAssertEqual(String(data: back, encoding: .utf8), "ping")
        XCTAssertEqual(try sail.connections().filter { $0.inboundTag == "control" }.count, 1)
        try handle.close()
        XCTAssertThrowsError(try sail.dial(outbound: "nope", network: .tcp, host: "127.0.0.1", port: echo)) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.notFound)
        }
        try sail.stop()
    }

    func testStartsAndStopsAgainAndAgain() throws {
        let sail = try Sail()
        let port = freePort()
        for _ in 0..<50 {
            try sail.start(config: config(port: port))
            try sail.stop()
        }
        XCTAssertTrue(true)
    }

    func testABadConfigurationSaysWhy() throws {
        let sail = try Sail()
        XCTAssertThrowsError(try sail.start(config: "{ \"outbounds\": 1 }")) { error in
            let error = error as? SailError
            XCTAssertEqual(error?.code, SailError.config)
            XCTAssertFalse(error?.message.isEmpty ?? true)
        }
        XCTAssertEqual(try sail.state().state, "failed")
        XCTAssertThrowsError(try Sail(settings: "{\"nothing\": 1}"))
    }
}

/// Each key of `json` (snake_case) is a property of `value`, and so for
/// the objects within.
func everyKey(_ json: Any, isIn value: Any, at path: String) {
    func camel(_ key: String) -> String {
        let parts = key.split(separator: "_")
        return parts.enumerated().map { $0.offset == 0 ? String($0.element) : $0.element.capitalized }.joined()
    }
    func unwrapped(_ any: Any) -> Any? {
        let mirror = Mirror(reflecting: any)
        guard mirror.displayStyle == .optional else { return any }
        return mirror.children.first.map { unwrapped($0.value) } ?? nil
    }
    guard let value = unwrapped(value) else { return }
    if let object = json as? [String: Any] {
        let mirror = Mirror(reflecting: value)
        // A dictionary model (keyed by name) is not a struct to look into.
        guard mirror.displayStyle == .struct else { return }
        let properties = Dictionary(mirror.children.compactMap { child in child.label.map { ($0, child.value) } },
                                    uniquingKeysWith: { a, _ in a })
        for (key, inner) in object {
            guard let property = properties[camel(key)] else {
                XCTFail("\(path)/\(key): no property \(camel(key)) in \(type(of: value))")
                continue
            }
            everyKey(inner, isIn: property, at: "\(path)/\(key)")
        }
    } else if let array = json as? [Any], let values = value as? [Any] {
        for (n, (inner, element)) in zip(array, values).enumerated() {
            everyKey(inner, isIn: element, at: "\(path)/\(n)")
        }
    }
}
