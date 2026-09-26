/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * C++ implementation of Dacar, a decentralized, offline-first authorization
 * policy plane for Reticulum networks: a tuple-based policy layer built on an
 * LWW-Element-Set CRDT, designed for delay-tolerant mesh networks and
 * constrained (microReticulum-class) nodes.
 *
 * Object and relation labels are stored only as salted HMAC-SHA256 hashes
 * (§3.3 Namespace Label Privacy), Threshold Groups may act as N-of-M Issuers
 * (§4.1), and the state is bounded by Time-Horizon Tombstone Pruning (§9).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Dacar/Version.h"
#include "Dacar/Containers.h"
#include "Dacar/Naming.h"
#include "Dacar/Namespace.h"
#include "Dacar/Hlc.h"
#include "Dacar/Tuple.h"
#include "Dacar/Threshold.h"
#include "Dacar/Operation.h"
#include "Dacar/Verifier.h"
#include "Dacar/Config.h"
#include "Dacar/Crdt.h"
#include "Dacar/Engine.h"
#include "Dacar/Delta.h"
