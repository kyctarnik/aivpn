package com.aivpn.client

import android.util.Base64
import org.json.JSONObject

data class ParsedConnectionKey(
    val server: String,
    val serverKey: String,
    val psk: String?,
    val vpnIp: String,
    val serverVpnIp: String,
    val prefixLen: Int,
    val mtu: Int,
    /** Base64 (standard) ed25519 server signing/verifying key, or null. Enables
     * signature verification of ServerHello / MaskUpdate / bootstrap descriptors. */
    val serverSigningKey: String? = null,
)

object ConnectionKeyParser {

    /**
     * Parse connection key: aivpn://BASE64URL({"s":"host:port","k":"...","p":"...","i":"...","n":{...}})
     * Returns null on any parse/validation error.
     */
    fun parse(key: String): ParsedConnectionKey? {
        val raw = key.trim()
        val payload = if (raw.startsWith("aivpn://")) raw.removePrefix("aivpn://") else raw
        return try {
            val jsonBytes = Base64.decode(
                payload,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
            )
            val json = JSONObject(String(jsonBytes))
            val server = json.getString("s")
            val serverKey = json.getString("k")
            val psk = json.optString("p").takeUnless { it.isNullOrBlank() }
            val serverSigningKey = json.optString("sk").takeUnless { it.isNullOrBlank() }
            val networkConfig = json.optJSONObject("n")
            val vpnIp = networkConfig?.optString("client_ip")?.takeUnless { it.isNullOrBlank() }
                ?: json.optString("i").takeUnless { it.isNullOrBlank() } ?: return null
            val serverVpnIp = networkConfig?.optString("server_vpn_ip")?.takeUnless { it.isNullOrBlank() }
                ?: "10.0.0.1"
            val prefixLen = networkConfig?.optInt("prefix_len", 24) ?: 24
            val mtu = networkConfig?.optInt("mtu", 1346) ?: 1346

            if (!isValidIpv4(vpnIp) || !isValidIpv4(serverVpnIp) || prefixLen !in 1..30 || mtu !in 576..1500) {
                return null
            }

            ParsedConnectionKey(server, serverKey, psk, vpnIp, serverVpnIp, prefixLen, mtu, serverSigningKey)
        } catch (_: Exception) {
            null
        }
    }

    /** Extract the server host (without port) from a connection key string, or "" on failure. */
    fun serverAddrFrom(key: String): String {
        val parsed = parse(key) ?: return ""
        val server = parsed.server
        // IPv6 bracketed notation: [::1]:443 -> ::1
        if (server.startsWith("[")) {
            val end = server.indexOf(']')
            return if (end > 1) server.substring(1, end) else server
        }
        return server.substringBeforeLast(':').ifEmpty { server }
    }

    private fun isValidIpv4(value: String): Boolean {
        val parts = value.split(".")
        if (parts.size != 4) return false
        return parts.all { part ->
            val n = part.toIntOrNull() ?: return false
            n in 0..255
        }
    }
}
