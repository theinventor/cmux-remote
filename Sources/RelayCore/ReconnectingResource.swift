/// Owns a single cached resource (e.g. a `CMUXClient`) and transparently
/// re-opens it when it is no longer alive. Concurrent `get()` callers that
/// arrive while a dial is in flight share that one dial (single-flight).
///
/// - Note: `isAlive` may be invoked concurrently on the same cached value
///   (e.g. when multiple `get()` callers race to check liveness), so callers
///   must make it safe for concurrent use on the same value.
public actor ReconnectingResource<R: Sendable> {
    private var cached: R?
    private var inFlight: Task<R, Error>?
    private let open: @Sendable () async throws -> R
    private let isAlive: @Sendable (R) async -> Bool

    public init(open: @escaping @Sendable () async throws -> R,
                isAlive: @escaping @Sendable (R) async -> Bool) {
        self.open = open
        self.isAlive = isAlive
    }

    public func get() async throws -> R {
        if let c = cached, await isAlive(c) { return c }
        cached = nil
        if let t = inFlight { return try await t.value }
        // Unstructured on purpose: cancelling any single waiter must not abort
        // the shared dial that the other concurrent waiters are awaiting.
        let t = Task { try await self.open() }
        inFlight = t
        defer { inFlight = nil }
        let c = try await t.value
        cached = c
        return c
    }

    public func invalidate() {
        cached = nil
    }
}
