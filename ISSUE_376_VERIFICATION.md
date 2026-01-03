# Issue #376 Verification Report

## Issue Description
**GitHub Issue**: https://github.com/snort3/snort3/issues/376  
**Title**: alert_json file rollover does not happen at JSON boundary

### Problem
When `alert_json` plugin is used with a non-zero `limit` value, file rotation occurs when the size exceeds the limit. However, rotation was happening mid-JSON object, causing alerts to be split across two files:
- Last line of old file: incomplete JSON (e.g., ending with partial b64_data)
- First line of new file: incomplete JSON (e.g., starting with remaining b64_data)

This resulted in two invalid JSON lines that cannot be parsed.

## Fix Implementation

### Code Changes

#### 1. TextLog Defer Rollover Mechanism
**File**: `src/log/text_log.h`
- Added `TextLog_DeferRollover()` function declaration (line 63)

**File**: `src/log/text_log.cc`
- Added `defer_rollover` boolean field to `TextLog` struct (line 59)
- Modified `TextLog_Flush()` to check `defer_rollover` flag before rolling (line 198):
  ```cpp
  if ( !txt->defer_rollover and txt->maxFile and txt->size + txt->pos > txt->maxFile )
      TextLog_Roll(txt);
  ```
- Implemented `TextLog_DeferRollover()` function (lines 325-328):
  ```cpp
  void TextLog_DeferRollover(TextLog* const txt, bool defer)
  {
      txt->defer_rollover = defer;
  }
  ```

#### 2. Alert JSON Logger Integration
**File**: `src/loggers/alert_json.cc`
- Modified `JsonLogger::alert()` function (lines 821-837):
  ```cpp
  void JsonLogger::alert(Packet* p, const char* msg, const Event& event)
  {
      Args a = { p, msg, event, false };
      
      TextLog_DeferRollover(json_log, true);   // DEFER ROLLOVER
      TextLog_Putc(json_log, '{');

      for ( JsonFunc f : fields )
      {
          f(a);
          a.comma = true;
      }

      TextLog_Print(json_log, " }\n");
      TextLog_DeferRollover(json_log, false);  // RE-ENABLE ROLLOVER
      TextLog_Flush(json_log);
  }
  ```

## How the Fix Works

### Execution Flow

1. **Before JSON Write** (line 825):
   - `TextLog_DeferRollover(json_log, true)` sets the defer flag
   - This prevents any rollover during the JSON object write

2. **During JSON Write** (lines 826-834):
   - `TextLog_Putc()`, `TextLog_Print()`, `TextLog_Write()` may trigger intermediate buffer flushes
   - Each flush calls `TextLog_Flush()` which checks the `defer_rollover` flag
   - Since `defer_rollover == true`, the rollover is skipped even if file size exceeds limit
   - Data continues to be written to the current file

3. **After Complete JSON** (line 835):
   - `TextLog_DeferRollover(json_log, false)` clears the defer flag
   - The complete JSON object is now in the buffer/file

4. **Final Flush** (line 836):
   - `TextLog_Flush()` is called
   - Now `defer_rollover == false`, so rollover CAN happen
   - If file size exceeds limit, rollover occurs AFTER the complete JSON object

### Key Insight
The rollover can only happen **between** complete JSON objects, never **during** a JSON object write. This ensures:
- Each JSON line in any file is complete and valid
- No JSON objects are split across file boundaries
- Large b64_data fields (the primary trigger for the bug) are kept intact

## Verification Status

### Code Review: ✓ VERIFIED
- [x] `defer_rollover` flag added to TextLog struct
- [x] `TextLog_Flush()` checks defer flag before rollover
- [x] `TextLog_DeferRollover()` function implemented
- [x] `JsonLogger::alert()` wraps JSON write with defer calls
- [x] Defer is set to `true` before JSON write starts
- [x] Defer is set to `false` after complete JSON object
- [x] Final flush called after defer is disabled

### Implementation Correctness: ✓ VERIFIED
The fix correctly addresses the root cause:
- **Root Cause**: File rollover could occur during any buffer flush, including mid-JSON
- **Solution**: Defer rollover flag prevents rotation during JSON object serialization
- **Result**: Rollover only occurs at JSON boundaries (between complete objects)

### Edge Cases Handled: ✓ VERIFIED
1. **Large b64_data fields**: Multiple buffer flushes during b64_data write are protected
2. **Small buffer size**: Even with frequent flushes, defer flag prevents mid-JSON rollover
3. **File size exceeded during JSON**: Data is written anyway, rollover deferred until after
4. **Multiple JSON objects**: Each object independently protected by defer mechanism

## Conclusion

**Issue #376 is FIXED** ✓

The implementation correctly prevents JSON objects from being split during file rollover by:
1. Deferring rollover before starting JSON serialization
2. Allowing all intermediate flushes to write without rolling
3. Re-enabling rollover only after the complete JSON object is written
4. Performing rollover (if needed) between JSON objects

This ensures that all JSON lines in all rotated files remain valid and parseable, even with:
- Very large b64_data payloads (400+ characters as mentioned in the issue)
- Small file size limits that would normally trigger frequent rollovers
- Small buffer sizes that cause multiple flushes per JSON object

The fix is minimal, focused, and solves the exact problem described in issue #376.
