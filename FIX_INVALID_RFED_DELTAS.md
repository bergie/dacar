# Fix for Invalid RFed Deltas Corrupting State

## Summary

Dacar 1.2.1 fixed a critical issue where malformed deltas (e.g., old-style batched payloads) from RFed could corrupt the authorization state. The fix includes:

1. **Strengthened validation** in `Operation.from_payload()` to match the JavaScript implementation
2. **Rejection logging** in `DeltaReceiver.apply_payload()` to help debug sync issues
3. **New `dacar validate` command** to detect corrupted state

## How It Works

### Validation
The strengthened validation now explicitly checks each field's type:
- Issuer, grantee, relation_hash must be exactly 16 bytes
- Action must be 0 (REVOKE) or 1 (GRANT)
- HLC must be a valid uint64 integer
- object_hashes must be an array of 16-byte blobs
- wildcard must be a boolean
- signatures must be an array of 64-byte blobs

Any deviation produces a clear error message like:
```
issuer must be a 16-byte binary blob, got list
object_hashes[0] must be 16 bytes, got str with length 9
```

### Logging
During sync, rejected deltas are logged:
```
dacar: rejected malformed delta: issuer must be a 16-byte binary blob, got list
dacar: rejected delta: verification failed or stale/future
```

This helps identify if old-style malformed deltas are still in RFed storage.

### Sync Behavior
The sync process processes each blob independently:
- Valid deltas are applied to state
- Invalid deltas are rejected and logged
- Processing continues after rejections (no early termination)

## Investigating Your Issue

Your symptoms suggest that corrupted data already exists in the client's state file:

**Admin machine:**
```
lille-oe (bbf0ba6…)  execute    blog:publish     self (146a819…)
lille-oe (bbf0ba6…)  execute    grib:request     self (146a819…)
lille-oe (bbf0ba6…)  execute    sys:command      self (146a819…)
```

**Client machine:**
```
? (3ea5aad…)         execute    blog:publish,grib:request,sys:command self (1e31f4c…)
```

The concatenated object string `blog:publish,grib:request,sys:command` suggests that an old-style malformed delta was applied before validation was strict.

### Steps to Diagnose and Fix

1. **Run validate on the client machine:**
   ```bash
   dacar validate
   ```

   This will check for suspicious patterns in the state.

2. **If corruption is detected, clean up the state:**

   Option A: Full reset (will need to re-sync)
   ```bash
   # Backup first
   cp -r ~/.dacar ~/.dacar.backup

   # Remove corrupted state
   rm ~/.dacar/state.msgpack

   # Re-sync from RFed
   dacar sync
   ```

   Option B: Manual inspection (if you have important local grants)
   - Export local grants: `dacar publish --outbox` (if any)
   - Then do Option A
   - Re-apply exported grants

3. **Monitor sync for rejections:**
   ```bash
   dacar sync
   ```

   Watch for stderr messages about rejected deltas. If you see them, RFed still has old-style malformed payloads in storage.

## Testing

All existing tests pass with the changes:
- `python3 -m unittest tests.test_operation` - 11 tests OK
- `python3 -m unittest tests.test_delta` - 13 tests OK
- Full test suite: 337 tests OK

## Migration to JavaScript

The same validation pattern should be applied to the JavaScript implementation to ensure cross-language consistency. The Python implementation now mirrors the JS validation approach with `_expect_bytes()` / `_expect_bool()` helpers matching JS `expectBytes()` / `expectBool()`.

## Future Work

1. Implement `--fix` flag for `dacar validate` to automatically remove corrupted entries
2. Add state migration tool to safely transition from corrupted to clean state
3. Consider adding checksum/hash of state file for integrity verification
