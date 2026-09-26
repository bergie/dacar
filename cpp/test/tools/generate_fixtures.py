#!/usr/bin/env python3
"""Generate C++ test fixtures for the Dacar C++ port (cpp/).

Run from anywhere; the script locates the canonical Python implementation
relative to its own path and writes test/fixtures/FixturesGen.h:

    python3 cpp/test/tools/generate_fixtures.py

The generated header is checked in, so the C++ Unity suites run without a
Python toolchain. Regenerate whenever the fixture scenarios below change.

Every byte-exact expectation (hashes, pre-images, signatures, transport
payloads, state snapshots) is computed by the canonical Python implementation
so the C++ port is validated against the reference bytes (work doc #16,
Phase 1 exit criteria).
"""

from __future__ import annotations

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PYTHON_IMPL = os.path.normpath(os.path.join(HERE, "..", "..", "python"))
sys.path.insert(0, PYTHON_IMPL)

from cryptography.hazmat.primitives import serialization as cryptography_serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from dacar.config import Config  # noqa: E402
from dacar.crdt import StateVector  # noqa: E402
from dacar.engine import Engine  # noqa: E402
from dacar.hlc import pack  # noqa: E402
from dacar.namespace import NamespaceHasher  # noqa: E402
from dacar.operation import Action, Operation  # noqa: E402
from dacar.threshold import ThresholdGroup, group_id as threshold_group_id  # noqa: E402
from dacar.tuple import Tuple  # noqa: E402
from dacar import serialization  # noqa: E402

# --- fixture identities and salts -------------------------------------------

SALT = bytes(range(32))
LEGACY_SALT = bytes(reversed(range(32)))
SALT2 = bytes([0x0A] * 32)

HASHES = [bytes([i]) * 16 for i in range(1, 9)]  # 8 distinct 16-byte ids

KEY_COUNT = 6


def key_at(i: int):
    seed = hashlib.sha256(f"dacar-fixture-key-{i}".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        cryptography_serialization.Encoding.Raw, cryptography_serialization.PublicFormat.Raw
    )
    return seed, priv, pub


KEYS = [key_at(i) for i in range(KEY_COUNT)]


def hx(data: bytes) -> str:
    return data.hex()


def hxs(items) -> str:
    return ";".join(hx(i) for i in items)


def fix_hlc(ms: int, logical: int = 0) -> int:
    return pack(ms, logical)


# --- case accumulators -------------------------------------------------------

ns_relation_cases = []
ns_object_cases = []
ns_idtag_cases = []
covers_cases = []
hlc_cases = []
tuple_cases = []
group_cases = []
op_cases = []       # (comment, salt, object, relation, grantee_idx, issuer_idx, action, hlc, seed_idxs, preimage, payload)
state_cases = []    # dicts
engine_cases = []   # dicts
batch_cases = []    # (comment, payload_hexs, expected_hex)


# --- §3.3 namespace cases ----------------------------------------------------

for salt, salt_name in ((SALT, "primary"), (LEGACY_SALT, "legacy"), (SALT2, "alt")):
    hasher = NamespaceHasher(salt)
    for relation in ("admin", "calibrate", "-calibrate", "read", "", "a:b"):
        ns_relation_cases.append((hx(salt), relation, hx(hasher.hash_relation(relation))))
    for obj in (
        "sensor:wind",
        "sensor:*",
        "*",
        "sensor",
        "vessel:2301234:buzzer",
        "",
        "a::b",
        ":a",
        "sensor:wind:*",
        "x**:y",
    ):
        segs, wildcard = hasher.hash_object(obj)
        ns_object_cases.append((hx(salt), obj, wildcard, hxs(segs)))
    ns_idtag_cases.append((hx(salt), hx(hasher.id_tag)))

# covers(): prefix / exact / longer-than-request / mismatch
_h = NamespaceHasher(SALT)
_segs, _ = _h.hash_object("sensor:wind:north")
_covers_specs = [
    # (tuple object, tuple wildcard, request object, expected)
    ("sensor:wind", True, "sensor:wind:north", True),
    ("sensor:wind", True, "sensor:wind", True),
    ("sensor:wind:north", False, "sensor:wind:north", True),
    ("sensor:wind", False, "sensor:wind:north", False),
    ("sensor:wind:north", True, "sensor:wind", False),
    ("sensor:wind:west", False, "sensor:wind:north", False),
    ("*", True, "anything:at:all", True),
    ("*", True, "", True),  # root wildcard covers the single-empty-segment object
]
for tup_obj, wildcard, req_obj, expected in _covers_specs:
    tup_hashes, _ = _h.hash_object(tup_obj)
    req_hashes, _ = _h.hash_object(req_obj)
    covers_cases.append((hxs(tup_hashes), wildcard, hxs(req_hashes), expected))

# --- §5.1 HLC cases -----------------------------------------------------------

hlc_cases = [
    (0, 0, pack(0, 0)),
    (1, 1, pack(1, 1)),
    (1_700_000_000_000, 0, pack(1_700_000_000_000, 0)),
    (1_700_000_000_000, 42, pack(1_700_000_000_000, 42)),
    (0xFFFFFFFFFFFF, 0xFFFF, pack(0xFFFFFFFFFFFF, 0xFFFF)),
    (0, 0xFFFF, pack(0, 0xFFFF)),
]

# --- §6.1 tuple cases ---------------------------------------------------------

_tuple_specs = [
    ("sensor:wind", "calibrate", 0, 1),
    ("sensor:*", "admin", 2, 3),
    ("*", "admin", 4, 5),
    ("vessel:2301234:buzzer", "sound", 6, 7),
    ("sensor", "", 0, 0),
]
for obj, rel, g, i in _tuple_specs:
    t = Tuple.from_plaintext(
        object_id=obj, relation=rel, grantee=HASHES[g], issuer=HASHES[i], hasher=_h
    )
    tuple_cases.append((obj, rel, hx(HASHES[g]), hx(HASHES[i]), hx(t.preimage()), hx(t.hash())))

# --- §4.1 threshold cases ------------------------------------------------------

_group_specs = [
    ([HASHES[0], HASHES[1]], 1),
    ([HASHES[1], HASHES[0]], 1),  # order invariance
    ([HASHES[0], HASHES[1]], 2),
    ([HASHES[0], HASHES[1], HASHES[2]], 2),
    ([HASHES[2], HASHES[1], HASHES[0]], 2),
]
for members, n in _group_specs:
    group_cases.append((hxs(members), n, hx(threshold_group_id(members, n))))
G21 = ThresholdGroup((HASHES[0], HASHES[1]), 1)

# --- §5.2/§5.3 operation cases --------------------------------------------------

_op_specs = [
    # (comment, salt, object, relation, grantee_idx, issuer_idx, action, hlc, seed_idxs)
    ("single grant", SALT, "sensor:wind", "calibrate", 2, 0, Action.GRANT, fix_hlc(1_700_000_000_001), [0]),
    ("single revoke", SALT, "sensor:wind", "calibrate", 2, 0, Action.REVOKE, fix_hlc(1_700_000_000_002), [0]),
    ("wildcard grant", SALT, "vessel:2301234:*", "sound", 3, 1, Action.GRANT, fix_hlc(1_700_000_000_003, 7), [1]),
    ("explicit deny", SALT, "buzzer", "-sound", 4, 0, Action.GRANT, fix_hlc(1_700_000_000_004), [0]),
    ("legacy salt grant", LEGACY_SALT, "sensor:wind", "calibrate", 2, 0, Action.GRANT, fix_hlc(1_700_000_000_005), [0]),
    ("threshold 2-of-3 grant", SALT, "sensor:rain", "read", 5, None, Action.GRANT, fix_hlc(1_700_000_000_006), [1, 2]),
    ("threshold 1-of-2 group", SALT, "sensor:*", "admin", 6, None, Action.GRANT, fix_hlc(1_700_000_000_007), [4]),
]
for comment, salt, obj, rel, g, issuer_idx, action, hlc, seed_idxs in _op_specs:
    hasher = NamespaceHasher(salt)
    if issuer_idx is None:
        # Threshold Group issuer: group id computed above
        issuer = G21.group_id if len(seed_idxs) == 1 else threshold_group_id([HASHES[0], HASHES[1], HASHES[2]], 2)
        member_pubs = (
            [KEYS[4][2], KEYS[5][2]] if len(seed_idxs) == 1 else [KEYS[0][2], KEYS[1][2], KEYS[2][2]]
        )
        threshold = 1 if len(seed_idxs) == 1 else 2
    else:
        issuer = HASHES[issuer_idx]
        member_pubs = [KEYS[seed_idxs[0]][2]]
        threshold = 1
    op = Operation(
        tuple=Tuple.from_plaintext(
            object_id=obj, relation=rel, grantee=HASHES[g], issuer=issuer, hasher=hasher
        ),
        action=action,
        hlc=hlc,
    )
    op = op.sign(*[KEYS[i][1] for i in seed_idxs])
    assert op.verify_threshold(member_pubs, threshold), comment
    op_cases.append(
        (
            comment,
            hx(salt),
            obj,
            rel,
            hx(HASHES[g]),
            hx(issuer),
            int(action),
            hlc,
            ";".join(str(i) for i in seed_idxs),
            member_pubs and ";".join(hx(k) for k in member_pubs) or "",
            threshold,
            hx(op.preimage()),
            hx(op.to_payload()),
        )
    )

# --- §6/§9 state cases -----------------------------------------------------------


def make_step(obj, rel, grantee, issuer, action, hlc, salt_index=0, now=None, expect=True):
    return {
        "object": obj,
        "relation": rel,
        "grantee": grantee,
        "issuer": issuer,
        "action": int(action),
        "hlc": hlc,
        "salt_index": salt_index,
        "now": now,
        "expect": expect,
    }


def run_state(steps, salt=SALT, legacy=(), horizon=180):
    state = StateVector(deletion_horizon_days=horizon)
    hashers = [NamespaceHasher(s) for s in [salt, *legacy]]
    for step in steps:
        op = Operation(
            tuple=Tuple.from_plaintext(
                object_id=step["object"],
                relation=step["relation"],
                grantee=step["grantee"],
                issuer=step["issuer"],
                hasher=hashers[step["salt_index"]],
            ),
            action=Action(step["action"]),
            hlc=step["hlc"],
        )
        now = step["now"] if step["now"] is not None else (step["hlc"] >> 16) + 10_000
        applied = state.apply(op, now_ms=now)
        assert applied == step["expect"], f"state step apply mismatch: {applied} != {step['expect']}"
    return state


NOW = 1_800_000_000_000
OLD = NOW - 400 * 24 * 60 * 60 * 1000  # beyond the 180-day horizon

# 1: grants and revocations, insertion order snapshot
steps = [
    make_step("sensor:wind", "calibrate", HASHES[2], HASHES[0], Action.GRANT, fix_hlc(NOW + 1)),
    make_step("sensor:rain", "read", HASHES[3], HASHES[0], Action.GRANT, fix_hlc(NOW + 2)),
    make_step("sensor:wind", "calibrate", HASHES[2], HASHES[0], Action.REVOKE, fix_hlc(NOW + 3)),
    make_step("sensor:wind", "calibrate", HASHES[2], HASHES[0], Action.GRANT, fix_hlc(NOW + 4)),  # re-grant
]
state_cases.append({
    "name": "grants_revokes_regrant",
    "salt": hx(SALT),
    "legacy": "",
    "horizon": 180,
    "steps": steps,
    "prune_now": -1,
    "expected": hx(run_state(steps).to_payload()),
    "pruned": 0,
    "expected_after": hx(run_state(steps).to_payload()),
})

# 2: LWW tie -> remove wins; older does not override newer
steps = [
    make_step("o", "r", HASHES[2], HASHES[0], Action.GRANT, fix_hlc(NOW, 5)),
    make_step("o", "r", HASHES[2], HASHES[0], Action.REVOKE, fix_hlc(NOW, 5)),  # exact tie
    make_step("o2", "r", HASHES[3], HASHES[0], Action.GRANT, fix_hlc(NOW, 9)),
    make_step("o2", "r", HASHES[3], HASHES[0], Action.REVOKE, fix_hlc(NOW, 3)),  # older remove loses
]
state_cases.append({
    "name": "tie_remove_wins_older_loses",
    "salt": hx(SALT),
    "legacy": "",
    "horizon": 180,
    "steps": steps,
    "prune_now": -1,
    "expected": hx(run_state(steps).to_payload()),
    "pruned": 0,
    "expected_after": hx(run_state(steps).to_payload()),
})

# 3: intake rejection (stale) + future skew rejection (§9, §12)
steps = [
    make_step("old", "r", HASHES[2], HASHES[0], Action.GRANT, fix_hlc(OLD), now=NOW, expect=False),
    make_step("future", "r", HASHES[2], HASHES[0], Action.GRANT, fix_hlc(NOW + 3 * 24 * 60 * 60 * 1000), now=NOW, expect=False),
    make_step("edge-future", "r", HASHES[3], HASHES[0], Action.GRANT, fix_hlc(NOW + 24 * 60 * 60 * 1000), now=NOW, expect=True),
]
state_cases.append({
    "name": "intake_rejections",
    "salt": hx(SALT),
    "legacy": "",
    "horizon": 180,
    "steps": steps,
    "prune_now": -1,
    "expected": hx(run_state(steps).to_payload()),
    "pruned": 0,
    "expected_after": hx(run_state(steps).to_payload()),
})

# 4: pairwise pruning deletes an old inactive pair; active grants survive
steps = [
    make_step("gone", "r", HASHES[2], HASHES[0], Action.GRANT, fix_hlc(OLD)),
    make_step("gone", "r", HASHES[2], HASHES[0], Action.REVOKE, fix_hlc(OLD + 10)),
    make_step("kept", "r", HASHES[3], HASHES[0], Action.GRANT, fix_hlc(OLD + 20)),
    make_step("recent", "r", HASHES[4], HASHES[0], Action.GRANT, fix_hlc(NOW - 1000)),
    make_step("recent", "r", HASHES[4], HASHES[0], Action.REVOKE, fix_hlc(NOW - 500)),  # recent revocation kept
]
state = run_state(steps)
pruned = state.prune(now_ms=NOW)
assert pruned == 1, pruned
state_cases.append({
    "name": "prune_pairwise",
    "salt": hx(SALT),
    "legacy": "",
    "horizon": 180,
    "steps": steps,
    "prune_now": NOW,
    "expected": hx(run_state(steps).to_payload()),
    "pruned": pruned,
    "expected_after": hx(state.to_payload()),
})

# 5: merge is commutative on byte-identical snapshots
steps_a = [
    make_step("a", "r", HASHES[2], HASHES[0], Action.GRANT, fix_hlc(NOW + 1)),
    make_step("shared", "r", HASHES[3], HASHES[0], Action.GRANT, fix_hlc(NOW + 2)),
]
steps_b = [
    make_step("shared", "r", HASHES[3], HASHES[0], Action.REVOKE, fix_hlc(NOW + 5)),
    make_step("b", "r", HASHES[4], HASHES[1], Action.GRANT, fix_hlc(NOW + 3)),
]
sa = run_state(steps_a)
sb = run_state(steps_b)
sa.merge(sb)
expected_merge = hx(sa.to_payload())
# Merging in the opposite direction yields the same *resolved state* but a
# different row order (insertion order is preserved), so byte equality is
# only asserted in one direction; the C++ suite checks the other direction
# semantically (same tuple hashes, same activity).
state_cases.append({
    "name": "merge_max_per_set",
    "salt": hx(SALT),
    "legacy": "",
    "horizon": 180,
    "steps": steps_a,
    "steps_b": steps_b,
    "prune_now": -1,
    "expected": expected_merge,
    "pruned": 0,
    "expected_after": expected_merge,
})

# 6: legacy-salt tuple in the snapshot (§10)
steps = [
    make_step("sensor:wind", "calibrate", HASHES[2], HASHES[0], Action.GRANT, fix_hlc(NOW), salt_index=1),
]
state_cases.append({
    "name": "legacy_salt_tuple",
    "salt": hx(SALT),
    "legacy": hx(LEGACY_SALT),
    "horizon": 180,
    "steps": steps,
    "prune_now": -1,
    "expected": hx(run_state(steps, legacy=(LEGACY_SALT,)).to_payload()),
    "pruned": 0,
    "expected_after": hx(run_state(steps, legacy=(LEGACY_SALT,)).to_payload()),
})

# --- §7 engine cases ---------------------------------------------------------------

E = 1_700_000_000_000


def engine_case(name, anchors, steps, requests, primary=SALT, legacy=(), groups=(), expect_notes=None):
    config_anchors = frozenset(anchors)
    state = StateVector()
    config_hashers = [NamespaceHasher(s) for s in [primary, *legacy]]
    for step in steps:
        op = Operation(
            tuple=Tuple.from_plaintext(
                object_id=step["object"],
                relation=step["relation"],
                grantee=step["grantee"],
                issuer=step["issuer"],
                hasher=config_hashers[step["salt_index"]],
            ),
            action=Action(step["action"]),
            hlc=step["hlc"],
        )
        applied = state.apply(op, now_ms=step["now"] if step["now"] is not None else E + 10_000)
        assert applied == step["expect"], name
    engine = Engine(
        Config(
            root_trust_anchors=config_anchors,
            primary_salt=primary,
            legacy_salts=tuple(legacy),
            threshold_groups=groups,
        ),
        state,
    )
    reqs = []
    for obj, rel, grantee, expected in requests:
        result = engine.evaluate(obj, rel, grantee)
        assert result == expected, f"{name}: evaluate({obj!r}, {rel!r}) -> {result}, expected {expected}"
        reqs.append((obj, rel, hx(grantee), expected))
    return {
        "name": name,
        "salt": hx(primary),
        "legacy": hxs(legacy),
        "anchors": hxs(anchors),
        "steps": steps,
        "requests": reqs,
    }


ROOT, A1, A2, BOB, ALICE = HASHES[0], HASHES[1], HASHES[2], HASHES[3], HASHES[4]

engine_cases.append(engine_case(
    "default_deny", [ROOT], [], [("sensor:wind", "calibrate", BOB, False)]
))
engine_cases.append(engine_case(
    "root_anchor_direct_grant",
    [ROOT],
    [make_step("sensor:wind", "calibrate", BOB, ROOT, Action.GRANT, fix_hlc(E + 1))],
    [("sensor:wind", "calibrate", BOB, True)],
))
engine_cases.append(engine_case(
    "wrong_grantee_denied",
    [ROOT],
    [make_step("sensor:wind", "calibrate", BOB, ROOT, Action.GRANT, fix_hlc(E + 1))],
    [("sensor:wind", "calibrate", ALICE, False)],
))
engine_cases.append(engine_case(
    "wrong_relation_denied",
    [ROOT],
    [make_step("sensor:wind", "read", BOB, ROOT, Action.GRANT, fix_hlc(E + 1))],
    [("sensor:wind", "write", BOB, False)],
))
engine_cases.append(engine_case(
    "delegated_admin_chain",
    [ROOT],
    [
        make_step("sensor:wind", "admin", A1, ROOT, Action.GRANT, fix_hlc(E + 1)),
        make_step("sensor:wind", "calibrate", BOB, A1, Action.GRANT, fix_hlc(E + 2)),
    ],
    [("sensor:wind", "calibrate", BOB, True)],
))
engine_cases.append(engine_case(
    "undelegated_issuer_denied",
    [ROOT],
    [make_step("sensor:wind", "calibrate", BOB, A1, Action.GRANT, fix_hlc(E + 1))],
    [("sensor:wind", "calibrate", BOB, False)],
))
engine_cases.append(engine_case(
    "wildcard_admin_cascades",
    [ROOT],
    [
        make_step("sensor:*", "admin", A1, ROOT, Action.GRANT, fix_hlc(E + 1)),
        make_step("sensor:wind:north", "calibrate", BOB, A1, Action.GRANT, fix_hlc(E + 2)),
    ],
    [("sensor:wind:north", "calibrate", BOB, True)],
))
engine_cases.append(engine_case(
    "exact_admin_does_not_cascade",
    [ROOT],
    [
        make_step("sensor:wind", "admin", A1, ROOT, Action.GRANT, fix_hlc(E + 1)),
        make_step("sensor:wind:north", "calibrate", BOB, A1, Action.GRANT, fix_hlc(E + 2)),
    ],
    [("sensor:wind:north", "calibrate", BOB, False)],
))
engine_cases.append(engine_case(
    "explicit_deny_overrides_allow",
    [ROOT],
    [
        make_step("sensor:wind", "calibrate", BOB, ROOT, Action.GRANT, fix_hlc(E + 1)),
        make_step("sensor:wind", "-calibrate", BOB, ROOT, Action.GRANT, fix_hlc(E + 2)),
    ],
    [("sensor:wind", "calibrate", BOB, False)],
))
engine_cases.append(engine_case(
    "exact_deny_overrides_wildcard_allow",
    [ROOT],
    [
        make_step("sensor:*", "calibrate", BOB, ROOT, Action.GRANT, fix_hlc(E + 1)),
        make_step("sensor:wind", "-calibrate", BOB, ROOT, Action.GRANT, fix_hlc(E + 2)),
    ],
    [("sensor:wind", "calibrate", BOB, False), ("sensor:rain", "calibrate", BOB, True)],
))
engine_cases.append(engine_case(
    "cycle_is_rejected",
    [ROOT],
    [
        make_step("o", "admin", A1, A2, Action.GRANT, fix_hlc(E + 1)),
        make_step("o", "admin", A2, A1, Action.GRANT, fix_hlc(E + 2)),
        make_step("o", "r", BOB, A1, Action.GRANT, fix_hlc(E + 3)),
    ],
    [("o", "r", BOB, False)],
))

# depth cap: a 16-hop chain exceeds max_depth=10
_ids = [bytes([i]) * 16 for i in range(1, 17)]
_depth_steps = [
    make_step("o", "admin", _ids[i + 1], _ids[i], Action.GRANT, fix_hlc(E + i)) for i in range(15)
]
_depth_steps.append(make_step("o", "r", BOB, _ids[15], Action.GRANT, fix_hlc(E + 100)))
engine_cases.append(engine_case(
    "depth_cap_rejects_overlong_chain",
    [ROOT],
    _depth_steps,
    [("o", "r", BOB, False)],
))

engine_cases.append(engine_case(
    "valid_chain_within_depth",
    [ROOT],
    [
        make_step("o", "admin", bytes([10]) * 16, ROOT, Action.GRANT, fix_hlc(E + 1)),
        make_step("o", "admin", bytes([20]) * 16, bytes([10]) * 16, Action.GRANT, fix_hlc(E + 2)),
        make_step("o", "read", BOB, bytes([20]) * 16, Action.GRANT, fix_hlc(E + 3)),
    ],
    [("o", "read", BOB, True)],
))
engine_cases.append(engine_case(
    "legacy_salt_tuple_still_matches",
    [ROOT],
    [make_step("sensor:wind", "calibrate", BOB, ROOT, Action.GRANT, fix_hlc(E), salt_index=1, now=E)],
    [("sensor:wind", "calibrate", BOB, True)],
    primary=SALT,
    legacy=(LEGACY_SALT,),
))
engine_cases.append(engine_case(
    "threshold_group_anchor",
    [G21.group_id],
    [make_step("sensor:wind", "calibrate", BOB, G21.group_id, Action.GRANT, fix_hlc(E + 1))],
    [("sensor:wind", "calibrate", BOB, True)],
))
engine_cases.append(engine_case(
    "shared_visited_bound_across_salts",
    [ROOT],
    [
        # Two parallel admin chains (one per salt) both rooted at ROOT via A1
        make_step("o", "admin", A1, ROOT, Action.GRANT, fix_hlc(E + 1)),
        make_step("o", "admin", A2, A1, Action.GRANT, fix_hlc(E + 2), salt_index=1),
        make_step("o", "read", BOB, A2, Action.GRANT, fix_hlc(E + 3), salt_index=1),
    ],
    [("o", "read", BOB, True)],
    primary=SALT,
    legacy=(LEGACY_SALT,),
))

# --- §11.1 batch payload cases --------------------------------------------------------

_payloads = [bytes.fromhex(op_cases[0][12]), bytes.fromhex(op_cases[3][12])]
batch_cases.append((
    "two_payloads",
    [hx(p) for p in _payloads],
    hx(serialization.packb(_payloads)),
))

# ==============================================================================
# C++ emission
# ==============================================================================


def cpp_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit_case_array(w, ctype, name, items, emit_item):
    w.write(f"\tstatic const {ctype} {name}[] = {{\n")
    for item in items:
        w.write(f"\t\t{emit_item(item)},\n")
    w.write("\t};\n")


def main() -> None:
    out_path = os.path.normpath(os.path.join(HERE, "..", "fixtures", "FixturesGen.h"))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as w:
        w.write(f'''/*
 * GENERATED FILE — do not edit by hand.
 *
 * Byte-exact fixture vectors for the Dacar C++ port's Unity suites,
 * generated by the canonical Python implementation via:
 *
 *     python3 cpp/test/tools/generate_fixtures.py
 */
#pragma once

#include <stdint.h>

#include <cstddef>

namespace DacarFixtures {{

	struct KeyCase {{
		const char* seed_hex;    // 32-byte Ed25519 seed
		const char* public_hex;  // derived 32-byte Ed25519 public key
	}};

	struct NsRelationCase {{
		const char* salt_hex;
		const char* relation;
		const char* hash_hex;
	}};

	struct NsObjectCase {{
		const char* salt_hex;
		const char* object;
		bool wildcard;
		const char* segments_hex; // ';'-joined 16-byte segment hashes
	}};

	struct NsIdTagCase {{
		const char* salt_hex;
		const char* tag_hex;
	}};

	struct CoversCase {{
		const char* tuple_hex;   // ';'-joined 16-byte segment hashes
		bool wildcard;
		const char* request_hex; // ';'-joined 16-byte segment hashes
		bool expected;
	}};

	struct HlcCase {{
		uint64_t physical;
		uint64_t logical;
		uint64_t packed;
	}};

	struct TupleCase {{
		const char* object;
		const char* relation;
		const char* grantee_hex;
		const char* issuer_hex;
		const char* preimage_hex;
		const char* hash_hex;
	}};

	struct GroupCase {{
		const char* members_hex; // ';'-joined 16-byte member hashes
		int threshold;
		const char* gid_hex;
	}};

	struct OpCase {{
		const char* comment;
		const char* salt_hex;
		const char* object;
		const char* relation;
		const char* grantee_hex;
		const char* issuer_hex;      // single identity or Threshold Group ID
		int action;                  // 0x00 Revoke / 0x01 Grant
		uint64_t hlc;
		const char* signing_seeds;   // ';'-joined indexes into KEYS
		const char* member_pubs_hex; // ';'-joined 32-byte public keys ('' for single)
		int threshold;               // 1 for single identity
		const char* preimage_hex;    // §5.2 signature pre-image
		const char* payload_hex;     // §5.3 transport payload
	}};

	struct StateStep {{
		const char* object;
		const char* relation;
		const char* grantee_hex;
		const char* issuer_hex;
		int action;
		uint64_t hlc;
		int salt_index;   // 0 = primary salt, 1.. = legacy salts in order
		int64_t now_ms;   // explicit wall clock passed to apply()
		bool expect;      // expected apply() return value
	}};

	struct StateCase {{
		const char* name;
		const char* salt_hex;
		const char* legacy_hex; // ';'-joined legacy salts ("" for none)
		int horizon_days;
		const StateStep* steps;
		size_t step_count;
		const StateStep* steps_b; // optional second stream for merge cases
		size_t step_b_count;
		int64_t prune_now_ms;     // -1 = do not prune
		size_t pruned;            // expected prune() return value
		const char* expected_hex;       // §13.4 snapshot before pruning
		const char* expected_after_hex; // §13.4 snapshot after pruning
	}};

	struct EngineRequest {{
		const char* object;
		const char* relation;
		const char* grantee_hex;
		bool expected;
	}};

	struct EngineCase {{
		const char* name;
		const char* salt_hex;
		const char* legacy_hex; // ';'-joined legacy salts ("" for none)
		const char* anchors_hex; // ';'-joined root trust anchor hashes
		const StateStep* steps;
		size_t step_count;
		const EngineRequest* requests;
		size_t request_count;
	}};

	struct BatchCase {{
		const char* comment;
		const char* payloads_hex; // ';'-joined §5.3 payload hex strings
		const char* expected_hex; // §11.1 batch encoding
	}};

''')
        # Keys
        w.write(f"\tconstexpr size_t KEY_COUNT = {KEY_COUNT};\n")
        emit_case_array(w, "KeyCase", "KEYS", [(hx(s), hx(p)) for s, _priv, p in KEYS],
                        lambda k: f'{{{cpp_str(k[0])}, {cpp_str(k[1])}}}')
        w.write(f"\tconstexpr size_t KEY_CASE_COUNT = {KEY_COUNT};\n")

        emit_case_array(w, "NsRelationCase", "NS_RELATION_CASES", ns_relation_cases,
                        lambda c: f'{{{cpp_str(c[0])}, {cpp_str(c[1])}, {cpp_str(c[2])}}}')
        w.write(f"\tconstexpr size_t NS_RELATION_CASE_COUNT = {len(ns_relation_cases)};\n")
        emit_case_array(w, "NsObjectCase", "NS_OBJECT_CASES", ns_object_cases,
                        lambda c: f'{{{cpp_str(c[0])}, {cpp_str(c[1])}, {str(c[2]).lower()}, {cpp_str(c[3])}}}')
        w.write(f"\tconstexpr size_t NS_OBJECT_CASE_COUNT = {len(ns_object_cases)};\n")
        emit_case_array(w, "NsIdTagCase", "NS_IDTAG_CASES", ns_idtag_cases,
                        lambda c: f'{{{cpp_str(c[0])}, {cpp_str(c[1])}}}')
        w.write(f"\tconstexpr size_t NS_IDTAG_CASE_COUNT = {len(ns_idtag_cases)};\n")
        emit_case_array(w, "CoversCase", "COVERS_CASES", covers_cases,
                        lambda c: f'{{{cpp_str(c[0])}, {str(c[1]).lower()}, {cpp_str(c[2])}, {str(c[3]).lower()}}}')
        w.write(f"\tconstexpr size_t COVERS_CASE_COUNT = {len(covers_cases)};\n")

        emit_case_array(w, "HlcCase", "HLC_CASES", hlc_cases,
                        lambda c: f'{{{c[0]}ULL, {c[1]}ULL, {c[2]}ULL}}')
        w.write(f"\tconstexpr size_t HLC_CASE_COUNT = {len(hlc_cases)};\n")

        emit_case_array(w, "TupleCase", "TUPLE_CASES", tuple_cases,
                        lambda c: f'{{{cpp_str(c[0])}, {cpp_str(c[1])}, {cpp_str(c[2])}, {cpp_str(c[3])}, {cpp_str(c[4])}, {cpp_str(c[5])}}}')
        w.write(f"\tconstexpr size_t TUPLE_CASE_COUNT = {len(tuple_cases)};\n")

        emit_case_array(w, "GroupCase", "GROUP_CASES", group_cases,
                        lambda c: f'{{{cpp_str(c[0])}, {c[1]}, {cpp_str(c[2])}}}')
        w.write(f"\tconstexpr size_t GROUP_CASE_COUNT = {len(group_cases)};\n")

        emit_case_array(w, "OpCase", "OP_CASES", op_cases,
                        lambda c: (
                            f'{{{cpp_str(c[0])}, {cpp_str(c[1])}, {cpp_str(c[2])}, {cpp_str(c[3])}, '
                            f'{cpp_str(c[4])}, {cpp_str(c[5])}, {c[6]}, {c[7]}ULL, {cpp_str(c[8])}, '
                            f'{cpp_str(c[9])}, {c[10]}, {cpp_str(c[11])}, {cpp_str(c[12])}}}'
                        ))
        w.write(f"\tconstexpr size_t OP_CASE_COUNT = {len(op_cases)};\n")

        # State + engine step arrays and cases (need named sub-arrays)
        w.write("\n\t// -- state cases (§6, §9) --\n")
        for idx, case in enumerate(state_cases):
            arr = f"STATE_STEPS_{idx}"
            emit_case_array(w, "StateStep", arr, case["steps"], emit_state_step)
            arr_b = None
            if "steps_b" in case:
                arr_b = f"STATE_STEPS_B_{idx}"
                emit_case_array(w, "StateStep", arr_b, case["steps_b"], emit_state_step)
            b_field = f"{arr_b}, {len(case['steps_b'])}" if arr_b else "nullptr, 0"
            w.write(
                f"\tstatic const StateCase STATE_CASES_{idx} = "
                f'{{{cpp_str(case["name"])}, {cpp_str(case["salt"])}, {cpp_str(case["legacy"])}, '
                f'{case["horizon"]}, {arr}, {len(case["steps"])}, {b_field}, '
                f'{case["prune_now"]}LL, {case["pruned"]}, {cpp_str(case["expected"])}, '
                f'{cpp_str(case["expected_after"])}}};\n'
            )
        w.write(f"\tstatic const StateCase* const STATE_CASES[] = {{\n")
        for idx in range(len(state_cases)):
            w.write(f"\t\t&STATE_CASES_{idx},\n")
        w.write("\t};\n")
        w.write(f"\tconstexpr size_t STATE_CASE_COUNT = {len(state_cases)};\n")

        w.write("\n\t// -- engine cases (§7, §10.2) --\n")
        for idx, case in enumerate(engine_cases):
            arr = f"ENGINE_STEPS_{idx}"
            emit_case_array(w, "StateStep", arr, case["steps"], emit_state_step)
            req_arr = f"ENGINE_REQUESTS_{idx}"
            emit_case_array(w, "EngineRequest", req_arr, case["requests"],
                            lambda r: f'{{{cpp_str(r[0])}, {cpp_str(r[1])}, {cpp_str(r[2])}, {str(r[3]).lower()}}}')
            w.write(
                f"\tstatic const EngineCase ENGINE_CASES_{idx} = "
                f'{{{cpp_str(case["name"])}, {cpp_str(case["salt"])}, {cpp_str(case["legacy"])}, '
                f'{cpp_str(case["anchors"])}, {arr}, {len(case["steps"])}, {req_arr}, {len(case["requests"])}}};\n'
            )
        w.write("\tstatic const EngineCase* const ENGINE_CASES[] = {\n")
        for idx in range(len(engine_cases)):
            w.write(f"\t\t&ENGINE_CASES_{idx},\n")
        w.write("\t};\n")
        w.write(f"\tconstexpr size_t ENGINE_CASE_COUNT = {len(engine_cases)};\n")

        emit_case_array(w, "BatchCase", "BATCH_CASES", batch_cases,
                        lambda c: f'{{{cpp_str(c[0])}, {cpp_str(";".join(c[1]))}, {cpp_str(c[2])}}}')
        w.write(f"\tconstexpr size_t BATCH_CASE_COUNT = {len(batch_cases)};\n")

        w.write("""
}
""")
    print(f"wrote {out_path}")
    print(f"  keys={KEY_COUNT} relations={len(ns_relation_cases)} objects={len(ns_object_cases)}")
    print(f"  covers={len(covers_cases)} hlc={len(hlc_cases)} tuples={len(tuple_cases)}")
    print(f"  groups={len(group_cases)} ops={len(op_cases)} state={len(state_cases)}")
    print(f"  engine={len(engine_cases)} batch={len(batch_cases)}")


def emit_state_step(step) -> str:
    # Always emit an explicit now_ms so C++ replay is fully deterministic.
    if step["now"] is not None:
        now = step["now"]
    else:
        now = (step["hlc"] >> 16) + 10_000
    return (
        f'{{{cpp_str(step["object"])}, {cpp_str(step["relation"])}, {cpp_str(hx(step["grantee"]))}, '
        f'{cpp_str(hx(step["issuer"]))}, {int(step["action"])}, {step["hlc"]}ULL, '
        f'{step["salt_index"]}, {now}LL, {str(step["expect"]).lower()}}}'
    )


if __name__ == "__main__":
    main()
