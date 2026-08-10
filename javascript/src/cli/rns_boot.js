/**
 * Node-only RNS boot helpers (work doc #6).
 *
 * Constructs and **connects** a mesh interface, then attaches it to a booted
 * `Reticulum` as the **default** interface — mirroring `@reticulum/node`'s
 * `rfed` CLI `attachInterface`. This is non-optional: without `connect()` the
 * interface's readable/writable streams are never set up and `_packetWriter`
 * stays `null`, so `TransportCore.broadcast()` silently skips it
 * (`if (!iface._packetWriter) continue`) and routed `sendPacket()` throws
 * `No route to host`. No traffic flows in either direction — the
 * `dacar sync --discover` "no rfed.node announce received within 30000ms"
 * timeout symptom, even when an rfed node is announcing on the mesh.
 *
 * Node-only (imports `@reticulum/node` interfaces); kept out of the
 * browser-portable `session.js`/`store.js` (see `test/cli-purity.test.js`).
 * The Node-only CLI bin (`dacar.js`) composes this with the portable helpers.
 */

import { Reticulum, setLogLevel, toHex } from "@reticulum/core";
import {
  AutoInterface,
  FileStorageAdapter,
  LocalClientInterface,
  TCPClientInterface,
} from "@reticulum/node";

/**
 * Boot a `Reticulum` with a connected, default-attached mesh interface.
 *
 * `shared` (default) prefers a running rnsd via
 * `LocalClientInterface.connectToSharedInstance()` (which internally
 * connects); if no shared instance is reachable it falls back to
 * `AutoInterface` so the node is still on the mesh — the same fallback the
 * rfed CLI uses. `auto` and `tcp` connect their respective interfaces
 * directly.
 *
 * @param {string} configDir Reticulum storage directory (identity/paths).
 * @param {"shared"|"auto"|"tcp"} iface Interface kind to attach.
 * @param {Object} [opts]
 * @param {boolean} [opts.verbose=false] Raise the Reticulum log threshold to
 *   `DEBUG` and log interface status + each validated announce the transport
 *   sees (dest/name-hash/hops), so a failing `--discover` shows whether any
 *   announces arrive at all and for which aspects.
 * @param {() => Promise<import("@reticulum/node").LocalClientInterface | null>} [opts.sharedFactory]
 *   Injectable shared-instance connector (tests).
 * @param {() => import("@reticulum/node").AutoInterface} [opts.autoFactory]
 *   Injectable AutoInterface factory (tests).
 * @param {(host: string, port: number) => import("@reticulum/node").TCPClientInterface} [opts.tcpFactory]
 *   Injectable TCPClientInterface factory (tests).
 * @returns {Promise<import("@reticulum/core").Reticulum>} A booted Reticulum
 *   with one connected default interface.
 */
export async function bootRns(configDir, iface, opts = {}) {
  if (opts.verbose) setLogLevel("DEBUG");
  const rns = new Reticulum({
    storageAdapter: new FileStorageAdapter(configDir),
  });
  const label = await attachInterface(rns, iface, opts);
  if (opts.verbose) {
    const ifaces = [...rns.transport.interfaces];
    const online = ifaces.filter((i) => i.online).length;
    process.stderr.write(
      `  rns: interface=${label} attached=${ifaces.length} online=${online}\n`,
    );
    // Surface every announce the transport validates, so a failed --discover
    // shows whether *any* announces are arriving (and for which aspects).
    rns.transport.addEventListener("announce", (event) => {
      const d = event.detail ?? {};
      const hops = d.packet?.hops ?? "?";
      process.stderr.write(
        `  announce: dest=${toHex(d.destinationHash ?? new Uint8Array())} ` +
          `name=${toHex(d.nameHash ?? new Uint8Array())} hops=${hops}\n`,
      );
    });
  }
  return rns;
}

/**
 * Construct, **connect**, and default-attach the requested interface kind.
 *
 * Connection is awaited before `addInterface(…, true)` so the interface's
 * streams are live by the time the transport binds it (and so a connection
 * failure surfaces immediately as a clear error rather than a 30s hang).
 *
 * @param {import("@reticulum/core").Reticulum} rns A booted Reticulum.
 * @param {"shared"|"auto"|"tcp"} iface Interface kind.
 * @param {Object} [opts] Factory overrides (see {@link bootRns}); `verbose`
 *   only affects the shared→auto fallback notice.
 * @returns {Promise<string>} A human-readable label for the attached interface.
 */
export async function attachInterface(rns, iface, opts = {}) {
  const makeAuto =
    opts.autoFactory ?? (() => new AutoInterface({ name: "auto" }));
  const makeTcp =
    opts.tcpFactory ??
    ((host, port) => new TCPClientInterface({ host, port }));
  const makeShared =
    opts.sharedFactory ?? (() => LocalClientInterface.connectToSharedInstance());

  if (iface === "auto") {
    const auto = makeAuto();
    await auto.connect();
    rns.addInterface(auto, true);
    return "AutoInterface";
  }
  if (iface === "tcp") {
    const host = process.env.RNS_HOST || "127.0.0.1";
    const port = parseInt(process.env.RNS_PORT || "42424", 10);
    const tcp = makeTcp(host, port);
    await tcp.connect();
    rns.addInterface(tcp, true);
    return `TCP ${host}:${port}`;
  }
  // shared (default): prefer a running rnsd; fall back to AutoInterface so the
  // node is still on the mesh when no daemon is present (mirrors the rfed CLI).
  const shared = await makeShared();
  if (shared) {
    rns.addInterface(shared, true);
    return "shared rnsd instance";
  }
  if (opts.verbose) {
    process.stderr.write(
      "  rns: shared instance unavailable; falling back to AutoInterface\n",
    );
  }
  const auto = makeAuto();
  await auto.connect();
  rns.addInterface(auto, true);
  return "AutoInterface (shared instance unavailable)";
}
