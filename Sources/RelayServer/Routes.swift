import Foundation
import NIOCore
import NIOHTTP1
import Crypto
import RelayCore
import SharedKit

/// Lightweight response envelope. The HTTP layer in M3.11 will translate
/// this into NIOHTTP1 head + body chunks; keeping it small here makes
/// `Routes` independent of the channel pipeline.
public struct HTTPResponseLite: Sendable {
    public var status: HTTPResponseStatus
    public var body: Data?
    public init(_ status: HTTPResponseStatus, body: Data? = nil) {
        self.status = status; self.body = body
    }
}

/// HTTP REST endpoints. Spec section 6.1.
///
/// Actor-isolated because authenticated paths (`apns`, `revoke`) and the
/// register flow can race with `ConfigStore.reload` and the WS handler.
/// The DeviceStore + AuthService it depends on are themselves
/// thread-safe, so this layer just sequences the request handling.
public actor Routes {
    private let deviceStore: DeviceStore
    private let config: RelayConfig
    private let auth: AuthService
    private let allowLocalhost: Bool
    private let audit: RelayAuditLog

    public init(deviceStore: DeviceStore,
                config: RelayConfig,
                auth: AuthService,
                allowLocalhost: Bool = Routes.defaultAllowLocalhost(),
                audit: RelayAuditLog = .shared)
    {
        self.deviceStore = deviceStore
        self.config = config
        self.auth = auth
        self.allowLocalhost = allowLocalhost
        self.audit = audit
    }

    /// Reads `CMUX_DEV_ALLOW_LOCALHOST=1` from the environment. When true,
    /// loopback callers (`127.0.0.1` / `::1`) bypass `tailscaled.whois` —
    /// macOS short-circuits packets to the local Tailscale IP through `lo0`,
    /// so the iOS Simulator on the same Mac can never produce a remote
    /// address tailscaled will recognise. We keep the bypass opt-in so it
    /// never ships to a production binding.
    public static func defaultAllowLocalhost() -> Bool {
        ProcessInfo.processInfo.environment["CMUX_DEV_ALLOW_LOCALHOST"] == "1"
    }

    /// Top-level dispatch. `deviceId` is `nil` until the HTTP layer has
    /// validated the bearer token (M3.11) — `Routes` itself does not
    /// re-validate, so authenticated paths short-circuit on `deviceId == nil`.
    public func handle(method: HTTPMethod,
                       path: String,
                       body: Data?,
                       deviceId: String?,
                       remoteAddr: String) async -> HTTPResponseLite
    {
        switch (method, path) {
        case (.GET, "/v1/health"):
            return .init(.ok, body: Data(#"{"ok":true}"#.utf8))

        case (.GET, "/v1/state"):
            return state()

        case (.POST, "/v1/devices/me/register"):
            return await registerNew(remoteAddr: remoteAddr)

        case (.POST, "/v1/devices/me/apns"):
            guard let did = deviceId,
                  deviceStore.lookup(deviceId: did) != nil else {
                return .init(.unauthorized)
            }
            return registerApns(deviceId: did, body: body)

        case (.DELETE, "/v1/devices/me"):
            guard let did = deviceId else { return .init(.unauthorized) }
            try? deviceStore.revoke(deviceId: did)
            return .init(.noContent)

        case (.POST, "/v1/realtime/token"):
            return await realtimeToken(remoteAddr: remoteAddr, body: body)

        case (.POST, "/v1/voice/log"):
            return await voiceLog(remoteAddr: remoteAddr, deviceId: deviceId, body: body)

        default:
            return .init(.notFound)
        }
    }

    // MARK: - GET /v1/state

    private func state() -> HTTPResponseLite {
        struct State: Encodable {
            let snippets: [RelayConfig.Snippet]
            let defaultFps: Int
            enum CodingKeys: String, CodingKey {
                case snippets, defaultFps = "default_fps"
            }
        }
        let s = State(snippets: config.snippets, defaultFps: config.defaultFps)
        let body = (try? JSONEncoder().encode(s)) ?? Data()
        return .init(.ok, body: body)
    }

    // MARK: - POST /v1/devices/me/apns

    private func registerApns(deviceId: String, body: Data?) -> HTTPResponseLite {
        struct Payload: Decodable {
            let apnsToken: String
            let env: String
            enum CodingKeys: String, CodingKey {
                case apnsToken = "apns_token", env
            }
        }
        guard let body,
              let p = try? JSONDecoder().decode(Payload.self, from: body),
              !p.apnsToken.isEmpty else {
            return .init(.badRequest)
        }
        guard p.env == "prod" || p.env == "sandbox" else {
            return .init(.badRequest)
        }
        try? deviceStore.setAPNsToken(deviceId: deviceId,
                                      token: p.apnsToken, env: p.env)
        return .init(.noContent)
    }

    // MARK: - POST /v1/realtime/token

    private func realtimeToken(remoteAddr: String, body: Data?) async -> HTTPResponseLite {
        guard let apiKey = DotEnv.get("OPENAI_API_KEY"), !apiKey.isEmpty else {
            audit.event("realtime.token.error", fields: [
                "remote_addr": .string(remoteAddr),
                "reason": .string("missing_openai_api_key"),
            ])
            return .init(.internalServerError, body: Data(#"{"error":"OPENAI_API_KEY not configured"}"#.utf8))
        }

        guard await authorizeRemote(remoteAddr: remoteAddr, event: "realtime.token") else {
            return .init(.forbidden)
        }

        let parsed = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        let model = parsed?["model"] as? String ?? "gpt-realtime-2"
        let voice = parsed?["voice"] as? String ?? "verse"
        audit.event("realtime.token.request", fields: [
            "remote_addr": .string(remoteAddr),
            "model": .string(model),
            "voice": .string(voice),
        ])

        let payload: [String: Any] = [
            "session": [
                "type": "realtime",
                "model": model,
                "audio": [
                    "output": ["voice": voice],
                ],
            ],
        ]

        var request = URLRequest(url: URL(string: "https://api.openai.com/v1/realtime/client_secrets")!)
        request.httpMethod = "POST"
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                audit.event("realtime.token.error", fields: [
                    "remote_addr": .string(remoteAddr),
                    "model": .string(model),
                    "voice": .string(voice),
                    "reason": .string("non_http_openai_response"),
                ])
                return .init(.internalServerError)
            }
            audit.event("realtime.token.response", fields: [
                "remote_addr": .string(remoteAddr),
                "model": .string(model),
                "voice": .string(voice),
                "status": .int(Int64(http.statusCode)),
                "response_bytes": .int(Int64(data.count)),
            ])
            return .init(HTTPResponseStatus(statusCode: http.statusCode), body: data)
        } catch {
            audit.event("realtime.token.error", fields: [
                "remote_addr": .string(remoteAddr),
                "model": .string(model),
                "voice": .string(voice),
                "reason": RelayAuditLog.string(String(describing: error)),
            ])
            return .init(.badGateway, body: Data(#"{"error":"failed to reach OpenAI"}"#.utf8))
        }
    }

    // MARK: - POST /v1/voice/log

    private func voiceLog(remoteAddr: String, deviceId: String?, body: Data?) async -> HTTPResponseLite {
        guard await authorizeRemote(remoteAddr: remoteAddr, event: "voice.log") else {
            return .init(.forbidden)
        }
        audit.event("voice.log", fields: [
            "remote_addr": .string(remoteAddr),
            "device_id": RelayAuditLog.optionalString(deviceId),
            "body": RelayAuditLog.bodyPreview(body),
        ])
        return .init(.accepted, body: Data(#"{"ok":true}"#.utf8))
    }

    // MARK: - POST /v1/devices/me/register

    private func registerNew(remoteAddr: String) async -> HTTPResponseLite {
        let peer: PeerIdentity
        if allowLocalhost, Self.isLoopback(remoteAddr), let login = config.allowLogin.first {
            // Dev bypass — see `defaultAllowLocalhost()`. The peer identity
            // is fabricated from the first allow_login so the simulator can
            // pair without traversing tailscaled. nodeKey is a stable
            // synthetic value so re-registering yields the same deviceId.
            peer = PeerIdentity(
                loginName: login,
                hostname: "localhost-dev",
                os: "ios-simulator",
                nodeKey: "cmux-dev-localhost:\(login)"
            )
        } else {
            do {
                peer = try await auth.whois(remoteAddr: remoteAddr)
            } catch RelayError.unauthorized {
                // tailscaled didn't recognize the peer at all — treat as
                // forbidden so the phone shows a clear "not on tailnet" UI
                // rather than a 5xx that suggests a relay bug.
                audit.event("device.register.reject", fields: [
                    "remote_addr": .string(remoteAddr),
                    "reason": .string("unauthorized_peer"),
                ])
                return .init(.forbidden)
            } catch {
                audit.event("device.register.error", fields: [
                    "remote_addr": .string(remoteAddr),
                    "reason": RelayAuditLog.string(String(describing: error)),
                ])
                return .init(.internalServerError)
            }

            guard config.allowLogin.contains(peer.loginName) else {
                audit.event("device.register.reject", fields: [
                    "remote_addr": .string(remoteAddr),
                    "login_name": .string(peer.loginName),
                    "hostname": .string(peer.hostname),
                    "reason": .string("login_not_allowed"),
                ])
                return .init(.forbidden)
            }
        }

        let deviceId = sha256Hex(peer.nodeKey)
        // Idempotent: rebinding the same node rotates the bearer so the
        // previous token (which may have leaked) is no longer valid.
        try? deviceStore.revoke(deviceId: deviceId)
        do {
            let token = try deviceStore.register(deviceId: deviceId,
                                                 loginName: peer.loginName,
                                                 hostname: peer.hostname,
                                                 apnsToken: nil)
            struct R: Encodable {
                let device_id: String
                let token: String
            }
            let body = try JSONEncoder().encode(R(device_id: deviceId, token: token))
            audit.event("device.register", fields: [
                "remote_addr": .string(remoteAddr),
                "device_id": .string(deviceId),
                "login_name": .string(peer.loginName),
                "hostname": .string(peer.hostname),
                "os": .string(peer.os),
            ])
            return .init(.ok, body: body)
        } catch {
            audit.event("device.register.error", fields: [
                "remote_addr": .string(remoteAddr),
                "device_id": .string(deviceId),
                "reason": RelayAuditLog.string(String(describing: error)),
            ])
            return .init(.internalServerError)
        }
    }

    private func authorizeRemote(remoteAddr: String, event: String) async -> Bool {
        if allowLocalhost, Self.isLoopback(remoteAddr) {
            audit.event("\(event).auth", fields: [
                "remote_addr": .string(remoteAddr),
                "mode": .string("localhost_bypass"),
            ])
            return true
        }

        do {
            let peer = try await auth.whois(remoteAddr: remoteAddr)
            guard config.allowLogin.contains(peer.loginName) else {
                audit.event("\(event).auth_reject", fields: [
                    "remote_addr": .string(remoteAddr),
                    "login_name": .string(peer.loginName),
                    "hostname": .string(peer.hostname),
                    "reason": .string("login_not_allowed"),
                ])
                return false
            }
            audit.event("\(event).auth", fields: [
                "remote_addr": .string(remoteAddr),
                "login_name": .string(peer.loginName),
                "hostname": .string(peer.hostname),
                "os": .string(peer.os),
            ])
            return true
        } catch {
            audit.event("\(event).auth_reject", fields: [
                "remote_addr": .string(remoteAddr),
                "reason": RelayAuditLog.string(String(describing: error)),
            ])
            return false
        }
    }
}

private func sha256Hex(_ s: String) -> String {
    SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
}

extension Routes {
    static func isLoopback(_ addr: String) -> Bool {
        addr == "127.0.0.1" || addr == "::1" || addr == "0:0:0:0:0:0:0:1"
    }
}
