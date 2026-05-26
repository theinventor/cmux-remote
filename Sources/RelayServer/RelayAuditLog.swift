import Foundation
import SharedKit

public enum AuditValue: Encodable, Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([AuditValue])
    case object([String: AuditValue])

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null:
            try container.encodeNil()
        case .bool(let value):
            try container.encode(value)
        case .int(let value):
            try container.encode(value)
        case .double(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }
}

public final class RelayAuditLog: @unchecked Sendable {
    public static let shared = RelayAuditLog()

    public let fileURL: URL
    private let queue = DispatchQueue(label: "cmux-relay.audit-log")
    private let fileManager = FileManager.default

    public init(fileURL: URL? = nil) {
        if let fileURL {
            self.fileURL = fileURL
            return
        }

        let envPath = ProcessInfo.processInfo.environment["CMUX_RELAY_LOG_DIR"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let logDirectory: URL
        if let envPath, !envPath.isEmpty {
            logDirectory = URL(fileURLWithPath: envPath, isDirectory: true)
        } else {
            logDirectory = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
                .appendingPathComponent(".cmuxremote", isDirectory: true)
                .appendingPathComponent("log", isDirectory: true)
        }
        self.fileURL = logDirectory.appendingPathComponent("events.jsonl")
    }

    public func event(_ event: String, fields: [String: AuditValue] = [:]) {
        queue.async { [fileURL, fileManager] in
            var payload = fields
            payload["ts"] = .string(Self.timestamp())
            payload["event"] = .string(event)
            payload["pid"] = .int(Int64(ProcessInfo.processInfo.processIdentifier))

            let encoder = JSONEncoder()
            guard let data = try? encoder.encode(payload) else { return }
            var line = data
            line.append(0x0a)

            do {
                try fileManager.createDirectory(
                    at: fileURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                if !fileManager.fileExists(atPath: fileURL.path) {
                    fileManager.createFile(atPath: fileURL.path, contents: nil)
                }
                let handle = try FileHandle(forWritingTo: fileURL)
                try handle.seekToEnd()
                try handle.write(contentsOf: line)
                try handle.close()
            } catch {
                // Audit logging must never take the relay down.
            }
        }
    }

    public static func string(_ value: String, maxLength: Int = 16_000) -> AuditValue {
        guard value.count > maxLength else { return .string(value) }
        let prefix = String(value.prefix(maxLength))
        return .string("\(prefix)...[truncated \(value.count - maxLength) chars]")
    }

    public static func optionalString(_ value: String?, maxLength: Int = 16_000) -> AuditValue {
        guard let value else { return .null }
        return string(value, maxLength: maxLength)
    }

    public static func fromJSON(_ value: JSONValue, key: String? = nil) -> AuditValue {
        if let key, isSensitiveKey(key) {
            return .string("[redacted]")
        }

        switch value {
        case .null:
            return .null
        case .bool(let value):
            return .bool(value)
        case .int(let value):
            return .int(value)
        case .double(let value):
            return .double(value)
        case .string(let value):
            return string(value)
        case .array(let values):
            return .array(values.map { fromJSON($0) })
        case .object(let values):
            var object: [String: AuditValue] = [:]
            for (key, value) in values {
                object[key] = fromJSON(value, key: key)
            }
            return .object(object)
        }
    }

    public static func bodyPreview(_ data: Data?, maxBytes: Int = 16_000) -> AuditValue {
        guard let data, !data.isEmpty else { return .null }
        if let object = try? JSONSerialization.jsonObject(with: data) {
            return fromAny(object)
        }

        let limited = Data(data.prefix(maxBytes))
        var text = String(decoding: limited, as: UTF8.self)
        if data.count > maxBytes {
            text += "...[truncated \(data.count - maxBytes) bytes]"
        }
        return .string(text)
    }

    public static func fromAny(_ value: Any, key: String? = nil) -> AuditValue {
        if let key, isSensitiveKey(key) {
            return .string("[redacted]")
        }

        switch value {
        case is NSNull:
            return .null
        case let value as String:
            return string(value)
        case let value as Bool:
            return .bool(value)
        case let value as Int:
            return .int(Int64(value))
        case let value as Int64:
            return .int(value)
        case let value as Double:
            return .double(value)
        case let value as NSNumber:
            let type = String(cString: value.objCType)
            if type == "c" {
                return .bool(value.boolValue)
            }
            if value.doubleValue.rounded() == value.doubleValue {
                return .int(value.int64Value)
            }
            return .double(value.doubleValue)
        case let value as [Any]:
            return .array(value.map { fromAny($0) })
        case let value as [String: Any]:
            var object: [String: AuditValue] = [:]
            for (key, value) in value {
                object[key] = fromAny(value, key: key)
            }
            return .object(object)
        default:
            return string(String(describing: value))
        }
    }

    private static func timestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }

    private static func isSensitiveKey(_ key: String) -> Bool {
        let normalized = key.lowercased()
        return normalized.contains("token")
            || normalized.contains("secret")
            || normalized.contains("authorization")
            || normalized.contains("api_key")
            || normalized.contains("apikey")
            || normalized.contains("bearer")
    }
}
