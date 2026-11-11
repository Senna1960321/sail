package io.github.peakpassvpn.sail

import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

/** A free loopback port. */
fun freePort(): Int = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }

/** A loopback server answering each connection with [answer], or an echo. */
fun serve(answer: ByteArray? = null): Int {
    val server = ServerSocket(0, 16, InetAddress.getLoopbackAddress())
    thread(isDaemon = true) {
        while (true) {
            val client = server.accept()
            thread(isDaemon = true) {
                client.use {
                    val buf = ByteArray(1024)
                    val n = it.getInputStream().read(buf)
                    if (n > 0) it.getOutputStream().write(answer ?: buf.copyOf(n))
                }
            }
        }
    }
    return server.localPort
}

/** "ping" through the SOCKS inbound at [port] to an echo; whether it came back. */
fun echoThroughSocks(port: Int): Boolean = runCatching {
    val echo = serve()
    Socket(InetAddress.getLoopbackAddress(), port).use { s ->
        s.soTimeout = 5_000
        val out = s.getOutputStream()
        val input = DataInputStream(s.getInputStream())
        out.write(byteArrayOf(5, 1, 0))
        input.readFully(ByteArray(2))
        out.write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, (echo shr 8).toByte(), echo.toByte()))
        val reply = ByteArray(10)
        input.readFully(reply)
        if (reply[1] != 0.toByte()) return false
        out.write("ping".toByteArray())
        val back = ByteArray(4)
        input.readFully(back)
        String(back) == "ping"
    }
}.getOrDefault(false)

fun config(port: Int) = """
    {
      "log": { "level": "info" },
      "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": $port }],
      "outbounds": [
        { "type": "selector", "tag": "sel", "outbounds": ["a", "b"] },
        { "type": "direct", "tag": "a" },
        { "type": "direct", "tag": "b" }
      ],
      "route": { "final": "sel" }
    }
""".trimIndent()

class SailTest {
    @Test
    fun theCapabilitiesNameTheBuild() {
        val capabilities = Sail.capabilities()
        assertTrue(capabilities.version.isNotEmpty())
        assertTrue("inbound-socks" in capabilities.features)
    }

    /**
     * The models read every field of the JSON sail publishes
     * (sail/src/control/json_snapshot.json, which sail's own test pins), and
     * decoded strictly: a field sail adds or renames that a model does not
     * follow fails here, not in a host.
     */
    @Test
    fun theModelsReadEveryFieldSailPublishes() {
        val strict = Json { ignoreUnknownKeys = false }
        val snapshot = strict.parseToJsonElement(
            java.io.File("../../sail/src/control/json_snapshot.json").readText()
        ).jsonObject
        val models: Map<String, kotlinx.serialization.KSerializer<*>> = mapOf(
            "capabilities" to InstanceCapabilities.serializer(),
            "sail_capabilities" to Capabilities.serializer(),
            "connection" to Connection.serializer(),
            "log" to Log.serializer(),
            "mode" to Mode.serializer(),
            "outbound" to Outbound.serializer(),
            "providers" to Providers.serializer(),
            "rule_sets" to RuleSets.serializer(),
            "state" to State.serializer(),
            "stop_report" to StopReport.serializer(),
            "fault" to Fault.serializer(),
            "reload_report" to ReloadReport.serializer(),
            "routed" to Routed.serializer(),
            "connection_record" to ConnectionRecord.serializer(),
            "dns_exchange" to DnsExchange.serializer(),
            "group_switch" to GroupSwitch.serializer(),
            "dial_failed" to DialFailed.serializer(),
            "user_event" to UserEvent.serializer(),
            "system_change" to SystemChange.serializer(),
            "status" to Status.serializer(),
            "traffic" to Traffic.serializer(),
        )
        // What the management API answers with, or an event read as text.
        val notModelled = setOf("network", "users", "stats", "inbounds", "inbound_users")
        for ((key, value) in snapshot) {
            if (key in notModelled) continue
            val model = assertNotNull(models[key], "the snapshot's $key has no model here: add one, or say why not")
            strict.decodeFromJsonElement(model, value)
        }
    }

    @Test
    fun connectionRecordParentIsOptionalWithinItsRun() {
        val strict = Json { ignoreUnknownKeys = false }
        val fields = strict.parseToJsonElement(
            java.io.File("../../sail/src/control/json_snapshot.json").readText()
        ).jsonObject.getValue("connection_record").jsonObject.toMutableMap()
        fields.remove("parent_id")
        fun read(): ConnectionRecord = strict.decodeFromJsonElement(
            ConnectionRecord.serializer(), kotlinx.serialization.json.JsonObject(fields)
        )
        val legacy = read()
        assertEquals(null, legacy.parentId)
        fields["parent_id"] = kotlinx.serialization.json.JsonNull
        assertEquals(null, read().parentId)
        fields["parent_id"] = kotlinx.serialization.json.JsonPrimitive(6L)
        val attempt = read()
        assertEquals(6L, attempt.parentId)
        assertEquals(legacy.id, attempt.id)
        assertEquals(legacy.runMs, attempt.runMs)
    }

    /** What a newer sail adds, a field or a string value, does not fail. */
    @Test
    fun aNewerSailsJsonStillReads() {
        val connection = json.decodeFromString<Connection>(
            """
            {"id": 1, "network": "sctp", "inbound_type": "a-new-kind", "inbound_tag": "in",
             "source": "127.0.0.1:1", "destination": "example.com:443", "upload": 0, "download": 0,
             "start": 0, "chains": [], "a_field_from_later": {"nested": [1, 2]}}
            """.trimIndent()
        )
        assertEquals("sctp", connection.network)
        val capabilities = json.decodeFromString<InstanceCapabilities>(
            """{"has_tun": false, "opens_tun": false, "protects_sockets": false, "needs_network": false,
                "has_modes": false}"""
        )
        assertEquals(null, capabilities.version, "a field an older sail lacks takes its default")
    }

    @Test
    fun anInstanceIsDrivenFromKotlin() = runBlocking {
        Sail.create("{\"log_lines\": 100}").use { sail ->
            assertEquals("idle", sail.state().state)
            assertEquals(SailException.STATE, assertFailsWith<SailException> { sail.traffic() }.code)
            val port = freePort()
            sail.start(config(port))
            assertEquals("running", sail.state().state)
            assertEquals(SailException.STATE, assertFailsWith<SailException> { sail.start("{}") }.code)
            assertTrue(echoThroughSocks(port))
            assertTrue(sail.traffic().upTotal >= 4)

            assertEquals(listOf("sel", "a", "b"), sail.outbounds().map { it.tag })
            sail.select("sel", "b")
            assertEquals("b", sail.groups().first().group?.selected)
            assertEquals(
                SailException.INVALID_ARGUMENT,
                assertFailsWith<SailException> { sail.select("sel", "c") }.code,
            )
            assertEquals(Mode("Rule", listOf("Rule")), sail.mode())

            val ok = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".toByteArray()
            val url = "http://127.0.0.1:${serve(ok)}/"
            assertTrue(sail.delay("a", url) >= 1)

            val logs = withTimeout(10_000) { sail.logs(level = "info").first { it.reset } }
            assertTrue(logs.lines.isNotEmpty())

            assertEquals(null, sail.reloadReport(config(port)).recheck)
            val rechecked = sail.reloadReport(config(port), RecheckOpen.CLOSE_REJECTED)
            assertEquals(Recheck(), rechecked.recheck)

            sail.stop()
            assertEquals("stopped", sail.state().state)
            sail.start(config(port))
            assertTrue(echoThroughSocks(port))
            sail.stop()
        }
    }

    @Test
    fun statesAreFollowed() = runBlocking {
        val scope = this
        Sail.create().use { sail ->
            val running = scope.async {
                withTimeout(10_000) { sail.states().first { it.state == "running" } }
            }
            kotlinx.coroutines.yield()
            sail.start(config(freePort()))
            assertNotNull(running.await().startedAtMs)
            sail.stop()
        }
    }

    @Test
    fun aClientAnswersAsTheInstance() = runBlocking {
        val path = "/tmp/sail-kotlin-${ProcessHandle.current().pid()}.sock"
        Sail.create().use { sail ->
            sail.serve("{\"path\": \"$path\"}")
            sail.start(config(freePort()))
            Sail.connect("{\"path\": \"$path\"}").use { client ->
                assertEquals("running", client.state().state)
                assertEquals(sail.outbounds(), client.outbounds())
                client.select("sel", "b")
                assertEquals("b", sail.groups().first().group?.selected)
                assertEquals(
                    SailException.UNSUPPORTED,
                    assertFailsWith<SailException> { client.start("{}") }.code,
                )
                withTimeout(10_000) { client.statuses(100).first() }
            }
            sail.stop()
        }
    }

    @Test
    fun aCallbackOnSailsThreadReachesKotlin() {
        val protected = AtomicInteger()
        Sail.create(platform = Platform(protectSocket = { protected.incrementAndGet(); true })).use { sail ->
            val port = freePort()
            sail.start(config(port))
            assertTrue(echoThroughSocks(port))
            assertTrue(protected.get() >= 1, "the socket was not protected")
            sail.stop()
        }
    }

    @Test
    fun theHostSaysWhichAppOpenedAConnection() {
        val asked = AtomicInteger()
        val platform = Platform(findConnectionOwner = { query ->
            asked.incrementAndGet()
            assertEquals("tcp", query.network)
            ConnectionOwner(10123, packages = listOf("com.blocked"))
        })
        Sail.create(platform = platform).use { sail ->
            val port = freePort()
            sail.start("""
                {
                  "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": $port }],
                  "outbounds": [{ "type": "direct" }],
                  "route": { "rules": [{ "package_name": "com.blocked", "action": "reject" }] }
                }
            """.trimIndent())
            assertTrue(!echoThroughSocks(port), "the app's connection was not rejected")
            assertTrue(asked.get() >= 1)
            sail.stop()
        }
    }

    @Test
    fun providersAndRuleSetsAreToldAndUpdated() {
        Sail.create().use { sail ->
            sail.start("""
                {
                  "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": ${freePort()} }],
                  "outbounds": [{ "type": "selector", "tag": "g", "providers": "p" }, { "type": "direct", "tag": "direct" }],
                  "outbound_providers": [{ "type": "inline", "tag": "p",
                    "outbounds": [{ "type": "direct", "tag": "m1" }, { "type": "direct", "tag": "m2" }] }],
                  "route": {
                    "rule_set": [{ "type": "inline", "tag": "r", "rules": [{ "domain_suffix": ["a.example"] }] }],
                    "rules": [{ "rule_set": "r", "outbound": "direct" }]
                  }
                }
            """.trimIndent())
            val provider = sail.providers().single()
            assertEquals("p", provider.tag)
            assertEquals("inline", provider.source)
            assertEquals(2L, provider.members)
            sail.updateProvider("p")
            val error = assertFailsWith<SailException> { sail.updateProvider("nope") }
            assertEquals(SailException.NOT_FOUND, error.code)
            assertEquals("r", sail.ruleSets().single().tag)
            sail.updateRuleSet("r")
            sail.stop()
        }
    }

    @Test
    fun aDialGoesThroughTheOutboundNamed() {
        Sail.create().use { sail ->
            sail.start(config(freePort()))
            val echo = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
            val fd = sail.dial("a", "tcp", "127.0.0.1", echo.localPort)
            assertTrue(fd >= 0)
            assertEquals(1, sail.connections().count { it.inboundTag == "control" })
            val error = assertFailsWith<SailException> { sail.dial("nope", "tcp", "127.0.0.1", echo.localPort) }
            assertEquals(SailException.NOT_FOUND, error.code)
            sail.stop()
            echo.close()
        }
    }

    @Test
    fun startsAndStopsAgainAndAgain() {
        Sail.create().use { sail ->
            val port = freePort()
            repeat(50) {
                sail.start(config(port))
                sail.stop()
            }
        }
    }

    @Test
    fun aBadConfigurationSaysWhy() {
        Sail.create().use { sail ->
            val error = assertFailsWith<SailException> { sail.start("{ \"outbounds\": 1 }") }
            assertEquals(SailException.CONFIG, error.code)
            assertTrue(error.message!!.isNotEmpty())
            assertEquals("failed", sail.state().state)
        }
        assertFailsWith<SailException> { Sail.create("{\"nothing\": 1}") }
    }
}
