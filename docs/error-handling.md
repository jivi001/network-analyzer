# System Error Handling Matrix

Mapping errors, exception origins, logging behavior, user-visible messages, and recovery strategies.

| Error / Exception | Origin Subsystem | Exception Class | User-Visible Message | Recovery Behavior |
|-------------------|------------------|-----------------|----------------------|-------------------|
| **Invalid Target Address** | `core/scanner.py` | `ValueError` | `"Invalid target address or hostname: '{target}'"` | Scan aborted cleanly; user returned to settings prompt or CLI exits. |
| **Unknown Scan Profile** | `core/scanner.py` | `ValueError` | `"Unknown scan profile: '{profile}'"` | Scan aborted cleanly; error displayed; target validation state reset. |
| **Invalid BPF Filter Syntax** | `sentinel.py` | `ValueError` | `"Invalid BPF filter syntax: {err}"` | Capture fails to start; sniffer remains in `IDLE`/`STOPPED` state. |
| **Npcap / Libpcap Missing** | `utils/privileges.py` | `RuntimeError` | `"Npcap is not installed or service is not running."` | Sniffer startup blocked; user prompted with installation instructions. |
| **Nmap Not Found in PATH** | `utils/privileges.py` | `RuntimeError` | `"Nmap is not installed or not in PATH."` | Scanner menu option disabled with warning message. |
| **Path Traversal Export Vector** | `storage/exporter.py` | `ValueError` | `"Invalid export filename (path traversal detected)"` | Export aborted; no file written outside `exports/` folder. |
| **Corrupted JSON Import Schema**| `storage/importer.py` | `ValueError` | `"Invalid session JSON: missing required key '{key}'"` | Import transaction rolled back; no database corruption occurs. |
| **Rich Markup Escape Error** | `tui/dashboard.py` | `rich.errors.MarkupError` | Handled via `rich.markup.escape()` | Error messages containing `[` or `]` characters render safely without crashing Rich. |
| **Database Busy / Lock Error** | `storage/database.py` | `sqlite3.OperationalError` | Retry mechanism (3 retries with 100ms delay) | Connection retries under WAL mode; fails gracefully if lock persists. |
