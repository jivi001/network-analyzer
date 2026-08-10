# Extension Guide — How to Add Features Safely

Step-by-step instructions for extending `my-sentinel` without breaking existing architecture or tests.

## 1. Adding a New Signature Detection Rule

1. Open `rules/default_rules.yaml`.
2. Add a new rule entry under `rules:`:
   ```yaml
   - id: "RULE-006"
     name: "Insecure HTTP Authentication"
     severity: "HIGH"
     condition:
       protocol: "TCP"
       dst_port: 80
       info_contains: "Authorization: Basic"
     message: "Insecure cleartext HTTP Basic Authentication header detected"
   ```
3. Test rule loading by running `python -m pytest tests/test_audit_regressions.py`.

---

## 2. Adding a New Nmap Scan Profile

1. Open `utils/constants.py` and update the `SCAN_TYPES` dictionary:
   ```python
   "syn_stealth_fast": {
       "name": "Fast Stealth SYN",
       "args": "-sS -T4 --top-ports 100",
       "description": "Accelerated SYN scan top 100 ports",
       "requires_admin": True,
       "cost": "Fast / Moderate",
   }
   ```
2. Update `config.yaml` to include the default argument string under `scanner:`.
3. Add a unit test assertion in `tests/test_subsystem_stress.py` verifying `--host-timeout` application and allowlist inclusion.

---

## 3. Adding a New Database Query or Table

1. Open `storage/database.py`.
2. Add `CREATE TABLE IF NOT EXISTS` statement inside `_init_db()`.
3. Implement parameterized getter/setter methods on the `Database` class using `with self._get_connection() as conn:` context managers.
4. Add regression test in `tests/test_audit_regressions.py`.
