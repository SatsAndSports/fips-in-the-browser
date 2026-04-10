/* tslint:disable */
/* eslint-disable */

/**
 * A FIPS node running in the browser via WASM.
 *
 * Lifecycle:
 * 1. `new()` or `from_nsec()` — create node with a keypair.
 * 2. `initiate_handshake(remote_npub)` — returns msg1 wire bytes to send.
 * 3. Feed incoming messages to `process_incoming()`.
 * 4. Send all `responses` from the result back over the WebSocket.
 * 5. After handshake completes, use `send_data()` for outgoing data.
 */
export class FipsNode {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Initiate an end-to-end session with a remote node (Noise XK).
     *
     * `dest_npub` is the remote node's npub string.
     * Returns FMP wire packets to send over the WebSocket.
     */
    connect_session(dest_npub: string): Uint8Array;
    /**
     * Create from an existing nsec (bech32) or hex secret key.
     */
    static from_nsec(nsec: string): FipsNode;
    /**
     * Handle a raw DNS query packet and return a raw DNS response.
     *
     * Used by the browser bridge to intercept UDP port 53 queries from the
     * VM guest and resolve `.fips` names locally without hitting the network.
     * Returns `None` if the query is unparseable.
     */
    handle_dns_query(query_bytes: Uint8Array): Uint8Array | undefined;
    /**
     * Initiate a Noise IK handshake with a remote peer.
     *
     * `remote_npub` is the peer's npub string (bech32).
     * Returns the full FMP msg1 wire packet (114 bytes) to send.
     */
    initiate_handshake(remote_npub: string): Uint8Array;
    /**
     * Check if the link is established (handshake complete).
     */
    is_established(): boolean;
    /**
     * Check if a session is established with a given npub.
     */
    is_session_established(dest_npub: string): boolean;
    /**
     * List all sessions and their states (for UI display).
     */
    list_sessions(): any;
    /**
     * Create a new node with a random keypair.
     */
    constructor();
    /**
     * Get this node's hex node address.
     */
    node_addr_hex(): string;
    /**
     * Get this node's npub string.
     */
    npub(): string;
    /**
     * Process an incoming FMP message (from WebSocket binary frame).
     *
     * Returns a JS object with:
     * - `msg_type`: "msg2", "tree_announce", "filter_announce", "sender_report", etc.
     * - `responses`: array of FMP wire packets to send back
     * - `payload`: decrypted payload (if any)
     * - `info`: human-readable status
     */
    process_incoming(data: Uint8Array): any;
    /**
     * Remove sessions idle for more than `max_idle_secs` seconds.
     * Returns the number of sessions pruned.
     */
    prune_idle_sessions(max_idle_secs: number): number;
    /**
     * Explicitly remove a session (e.g., detected as stale).
     */
    remove_session(dest_npub: string): boolean;
    /**
     * Resolve a direct `<npub>.fips` name locally.
     */
    resolve_fips_name(name: string): any;
    /**
     * Send a raw IPv6 packet through an established session on port 256.
     */
    send_ipv6(dest_npub: string, packet: Uint8Array): Uint8Array;
    /**
     * Send an empty data packet to port 0 as a session-layer keepalive.
     */
    send_keepalive(dest_npub: string): Uint8Array;
    /**
     * Build keepalive packets for all established sessions.
     */
    send_keepalives(): any;
    /**
     * Send a chat message through an established session.
     *
     * Returns FMP wire packets to send over the WebSocket.
     */
    send_message(dest_npub: string, text: string): Uint8Array;
    /**
     * Send an ICMPv6 Echo Request through an established session.
     */
    send_ping(dest_npub: string): Uint8Array;
    /**
     * Get the receive-idle time for a specific session in milliseconds.
     * Returns undefined if no session exists for this npub.
     */
    session_idle_ms(dest_npub: string): number | undefined;
    /**
     * Enable or disable raw IPv6 passthrough mode.
     *
     * When enabled, incoming port-256 IPv6 shim packets are surfaced back to JS
     * as raw IPv6 packets instead of being handled internally for ICMPv6 ping.
     */
    set_ipv6_passthrough(enabled: boolean): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_fipsnode_free: (a: number, b: number) => void;
    readonly fipsnode_connect_session: (a: number, b: number, c: number) => [number, number, number, number];
    readonly fipsnode_from_nsec: (a: number, b: number) => [number, number, number];
    readonly fipsnode_handle_dns_query: (a: number, b: number, c: number) => [number, number];
    readonly fipsnode_initiate_handshake: (a: number, b: number, c: number) => [number, number, number, number];
    readonly fipsnode_is_established: (a: number) => number;
    readonly fipsnode_is_session_established: (a: number, b: number, c: number) => number;
    readonly fipsnode_list_sessions: (a: number) => [number, number, number];
    readonly fipsnode_new: () => number;
    readonly fipsnode_node_addr_hex: (a: number) => [number, number];
    readonly fipsnode_npub: (a: number) => [number, number];
    readonly fipsnode_process_incoming: (a: number, b: number, c: number) => [number, number, number];
    readonly fipsnode_prune_idle_sessions: (a: number, b: number) => number;
    readonly fipsnode_remove_session: (a: number, b: number, c: number) => number;
    readonly fipsnode_resolve_fips_name: (a: number, b: number, c: number) => [number, number, number];
    readonly fipsnode_send_ipv6: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly fipsnode_send_keepalive: (a: number, b: number, c: number) => [number, number, number, number];
    readonly fipsnode_send_keepalives: (a: number) => [number, number, number];
    readonly fipsnode_send_message: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly fipsnode_send_ping: (a: number, b: number, c: number) => [number, number, number, number];
    readonly fipsnode_session_idle_ms: (a: number, b: number, c: number) => number;
    readonly fipsnode_set_ipv6_passthrough: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
