# Fix: Reject invalid RFed deltas that corrupt state

## Problem
When syncing from RFed, invalid deltas can corrupt the authorization state:

1. On admin machine: 3 separate grants with correct grantee/issuer hashes
2. On client machine: 1 corrupted grant with:
   - Wrong grantee hash (`3ea5aad…` instead of `bbf0ba6…`)
   - Objects concatenated: `blog:publish,grib:request,sys:command`
   - Different issuer hash (`1e31f4c…` instead of `146a819…`)

This suggests old-style "bunched" deltas stored in RFed were accepted when they should have been rejected.

## Root Cause Analysis

The Python validation in `Operation.from_payload()` was checking field types but with less strict error messages than the JavaScript implementation. The key issue:

1. Corrupted state likely already exists in the client's `state.msgpack` file
2. The corruption happened when old-style malformed payloads were accepted (before strict validation)
3. Once written to state file, corrupted data persists even after validation is fixed
4. During sync, both valid AND invalid deltas may be in RFed storage - we need to accept valid ones and reject invalid ones

## Solution Implemented

### 1. Strengthened validation (prevent future corruption) ✓ DONE
Made Python validation match JavaScript implementation:
- Added `_expect_bytes()` and `_expect_bool()` helper functions
- Use explicit type checks before `bytes()` conversion
- Improved error messages to identify specific fields and issues

### 2. Added diagnostic logging ✓ DONE
- Added `log_rejections` parameter to `DeltaReceiver.apply_payload()`
- Enabled by default in `dacar sync` command
- Rejected deltas are logged to stderr with detailed error messages

### 3. State validation tool ✓ DONE
Added `dacar validate` command to:
- Detect suspicious patterns in state (many object segments, non-random hashes)
- Provide guidance on how to clean up corrupted state
- `--fix` flag (placeholder) for future automatic cleanup

## Files Changed

1. **python/dacar/operation.py**
   - Added `_expect_bytes()` and `_expect_bool()` helpers
   - Updated `from_payload()` with strict type checking
   - Improved error messages

2. **python/dacar/delta.py**
   - Added `log_rejections` parameter to `apply_payload()`
   - Logs both malformed payloads and verification failures

3. **python/dacar/cli/commands.py**
   - Updated `run_sync()` to enable rejection logging via `LoggingReceiver`
   - Added `cmd_validate()` function

4. **python/dacar/cli/__init__.py**
   - Added `validate` subcommand
   - Added `_cmd_validate()` wrapper

5. **CHANGELOG.md**
   - Documented security fixes in [Unreleased] section

## Testing

All tests pass:
- `python3 -m unittest tests.test_operation` - 11 tests OK
- `python3 -m unittest tests.test_delta` - 13 tests OK  
- Full test suite: 337 tests OK

Smoketests confirm:
- Malformed payloads are correctly rejected
- Valid deltas are still accepted
- Mixed valid/invalid blobs are processed correctly (valid applied, invalid rejected)

## How to Fix Your Corrupted State

### On the client machine:

1. **Run validate to check for corruption:**
   ```bash
   dacar validate
   ```

2. **If corruption is detected, clean up the state:**

   Option A: Full reset (will need to re-sync from RFed)
   ```bash
   # Backup first
   cp -r ~/.dacar ~/.dacar.backup

   # Remove corrupted state
   rm ~/.dacar/state.msgpack

   # Re-sync from RFed (watch for rejection messages)
   dacar sync
   ```

   Option B: Manual inspection (if you have important local-only grants)
   - Export local grants: `dacar publish --outbox` (if any)
   - Save the output to a file
   - Do Option A reset
   - Re-apply exported grants: `dacar apply <file>`

3. **Monitor for rejected deltas during sync:**
   ```bash
   dacar sync
   # Watch stderr for messages like:
   # dacar: rejected malformed delta: ...
   ```

   If you see rejections, RFed still has old-style malformed payloads in storage.

## Verification

After fixing the state, verify the grants are correct:
```bash
dacar grants --all
```

You should see:
- 3 separate grants (not 1)
- Correct grantee hash matching lille-oe
- Correct issuer hash
- Separate object strings (not concatenated)

## Future Work

1. Implement `--fix` flag for `dacar validate` to automatically remove corrupted entries
2. Add state migration tool to safely transition from corrupted to clean state
3. Consider adding checksum/hash of state file for integrity verification
4. Port same validation improvements to JavaScript implementation