"""Offline tests. All stores are in memory; native modules are replaced by fakes.

Run: python -B -m unittest -v test_mirai_bridge
No dependency installation, database files, native imports, network or pycache.
The ORM-shaped transaction double verifies adapter control flow and rollback,
not SQLAlchemy's implementation or live Mirai services.
"""
import copy
import io
import json
import logging
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mirai_bridge as bridge

T0 = 1_794_225_600_000
T1 = T0 + 3_600_000
SECRET = "DO_NOT_LEAK_PRIVATE_TOKEN"
FIELDS = {"ok", "status", "message", "balance", "signed", "credentialChanged"}


class Field:
    def __init__(self, name):
        self.name = name

    def __eq__(self, value):
        return lambda row: getattr(row, self.name, None) == value

    def in_(self, values):
        return lambda row: getattr(row, self.name, None) in values


class Account:
    id, platform, uid = Field("id"), Field("platform"), Field("uid")

    def __init__(self, **fields):
        self.__dict__.update(
            id=None, platform="loomy", uid="u1", name="Example", status="active",
            auth_json="{}", balance_remain=0, domain="cn",
            balance_synced_at=None, credits_synced_at=None, last_sync_at=None,
            credits_snapshot="", cool_until=None, breaker_until=None,
            degrade_until=None, ban_kind="", session_dead_fails=0,
            consecutive_fails=0, last_err_msg="", updated_at=None)
        self.__dict__.update(fields)


class Schedule:
    id, platform = Field("id"), Field("platform")

    def __init__(self, **fields):
        self.__dict__.update(id=None, platform=bridge.WPS,
                             task="wps_lingxi_checkin", enabled=1,
                             last_result="", last_run_at=None, next_run_at=None,
                             interval_minutes=60, timing_config=SECRET,
                             name=SECRET)
        self.__dict__.update(fields)


class Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *conditions):
        self.rows = [row for row in self.rows if all(c(row) for c in conditions)]
        return self

    def order_by(self, field):
        self.rows = sorted(self.rows, key=lambda r: getattr(r, field.name))
        return self

    def all(self):
        return self.rows


class Store:
    def __init__(self, accounts=(), schedules=()):
        self.rows = {Account: list(accounts), Schedule: list(schedules)}
        self.begins = self.commits = self.rollbacks = 0
        self.fail_commit = False

    def session(self):
        return Session(self)


class Session:
    def __init__(self, store):
        self.store = store
        self.rows = copy.deepcopy(store.rows)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def query(self, model):
        return Query(list(self.rows[model]))

    def add(self, row):
        self.rows[type(row)].append(row)

    def flush(self):
        for rows in self.rows.values():
            next_id = max((r.id or 0 for r in rows), default=0) + 1
            for row in rows:
                if row.id is None:
                    row.id = next_id
                    next_id += 1

    def commit(self):
        if self.store.fail_commit:
            raise RuntimeError(SECRET)
        self.store.commits += 1
        self.store.rows = copy.deepcopy(self.rows)

    def rollback(self):
        self.store.rollbacks += 1
        self.rows = copy.deepcopy(self.store.rows)

    def refresh(self, row):
        saved = next(r for r in self.store.rows[type(row)] if r.id == row.id)
        row.__dict__.update(copy.deepcopy(saved.__dict__))


def backend(store, executor=None):
    def begin(db):
        store.begins += 1
    return bridge.NativeBackend(store.session, Account, Schedule, executor, begin)


def account(platform="loomy", aid=1, status="active", auth=None, **kwargs):
    default = {"uid": "u1", "realm": "cn", "token": SECRET}
    if platform == bridge.WPS:
        default = {"uid": "u1", "realm": "cn", "cookie": "wps_sid=" + SECRET}
    return Account(id=aid, platform=platform, status=status,
                   auth_json=bridge.canonical(auth or default), **kwargs)


def upsert_record(**kwargs):
    record = {"platform": "loomy", "uid": "u1", "name": "New name",
              "auth": {"token": "new-private-token"}, "status": "active"}
    record.update(kwargs)
    return record


class TransformTests(unittest.TestCase):
    def test_canonical_hash_is_order_independent_and_unicode(self):
        self.assertEqual(bridge.auth_hash({"b": 2, "a": "中文"}),
                         bridge.auth_hash({"a": "中文", "b": 2}))
        self.assertNotEqual(bridge.auth_hash({"token": "a"}),
                            bridge.auth_hash({"token": "b"}))

    def test_loomy_normalization_and_outbound(self):
        raw = {"session": SECRET, "userid": "0007", "password": "password",
               "devid": "dev", "updatedAt": T1, "expires_at": T1 + 1000}
        native = bridge.normalize_auth("loomy", raw, "0007")
        out = bridge.agent_credentials("loomy", native, "0007")
        self.assertEqual(native["token"], SECRET)
        self.assertEqual(out["session"], SECRET)
        self.assertEqual(out["userid"], "0007")
        self.assertEqual(out["password"], "password")
        self.assertNotIn("token", raw)

    def test_raccoon_never_invents_refresh(self):
        for raw in ({"token": SECRET}, {"token": SECRET, "refresh_token": SECRET}):
            normalized = bridge.normalize_auth("raccoon", raw, "u1")
            exported = bridge.agent_credentials("raccoon", raw, "u1")
            self.assertNotIn("refresh_token", normalized)
            self.assertNotIn("refreshToken", exported)

    def test_raccoon_preserves_real_refresh_and_original_secret(self):
        raw = {"accessToken": SECRET, "refreshToken": "real-refresh",
               "expiresAt": T1 / 1000, "agent2api": {"deviceId": "device"}}
        data = bridge.normalize_auth("raccoon", raw, "u1")
        out = bridge.agent_credentials("raccoon", data, "u1")
        self.assertEqual(data["expires_at"], T1)
        self.assertEqual(out["deviceId"], "device")
        self.assertEqual(out["refreshToken"], "real-refresh")

    def test_raccoon_old_synthetic_refresh_not_promoted_after_rotation(self):
        raw = {"token": "old-access", "refresh_token": "old-access"}
        result = bridge.merged_auth("raccoon", "u1", raw, {"accessToken": "new-access"})
        self.assertEqual(result["token"], "new-access")
        self.assertNotIn("refresh_token", result)

    def test_parent_credential_clock_persisted_for_future_stale_detection(self):
        first = bridge.merge_plan(upsert_record(credential_at=T1))
        self.assertEqual(first["auth"]["credential_at"], T1)
        request = upsert_record(credential_at=T0,
                                expected_auth_hash=bridge.auth_hash(first["auth"]))
        with self.assertRaisesRegex(bridge.BridgeError, "stale_credentials"):
            bridge.merge_plan(request, first["auth"], "disabled")

    def test_merged_canonical_credentials_replace_old_native_priority_aliases(self):
        old = {"token": "old", "accessToken": "old", "refresh_token": "old-refresh",
               "refreshToken": "old-refresh"}
        result = bridge.merged_auth("raccoon", "u1", old,
                                    {"token": "new", "refresh_token": "new-refresh"})
        self.assertEqual(result["accessToken"], "new")
        self.assertEqual(result["refreshToken"], "new-refresh")
        result = bridge.merged_auth("codearts", "u1",
                                    {"access_key": "old", "access_key_id": "old"},
                                    {"access_key": "new"})
        self.assertEqual(result["access_key_id"], "new")

    def test_codearts_preserves_full_refresh_bundle(self):
        raw = {"access_key_id": "ak", "secret_access_key": "sk",
               "securityToken": "sts", "refreshToken": "rt",
               "dpopPrivateKey": "private", "dpopPublicKey": "public",
               "pkceCodeVerifier": "verifier", "expiresAt": T1}
        data = bridge.normalize_auth("codearts", raw, "u1")
        self.assertEqual(data["access_key"], "ak")
        self.assertEqual(data["secret_key"], "sk")
        self.assertEqual(data["dpop_private_key"], "private")
        self.assertEqual(data["pkce_code_verifier"], "verifier")
        out = bridge.agent_credentials("codearts", data, "u1")
        self.assertEqual(out["access_key_id"], "ak")
        self.assertEqual(out["secret_access_key"], "sk")

    def test_wps_sid_outbound(self):
        data = bridge.agent_credentials("wps_lingxi", {"sid": SECRET}, "u1")
        self.assertEqual(data["cookie"], "wps_sid=" + SECRET + "; uid=u1")

    def test_uid_conflict_and_truncation_refused(self):
        for uid in ("", " user ", "x" * 121, 123):
            with self.assertRaises(bridge.BridgeError):
                bridge.uid_value(uid)
        with self.assertRaisesRegex(bridge.BridgeError, "uid_mismatch"):
            bridge.normalize_auth("loomy", {"uid": "other", "token": SECRET}, "u1")

    def test_partial_credentials_preserve_native_private_fields(self):
        old = {"uid": "u1", "token": "old", "password": "password",
               "custom": {"a": 1, "b": 2}, "expires_at": T1}
        incoming = {"session": "new", "password": "",
                    "custom": {"b": None, "c": 3}}
        merged = bridge.merged_auth("loomy", "u1", old, incoming)
        self.assertEqual(merged["token"], "new")
        self.assertEqual(merged["password"], "password")
        self.assertEqual(merged["custom"], {"a": 1, "b": 2, "c": 3})
        self.assertEqual(old["token"], "old")

    def test_status_never_resurrects_disabled_or_enables_backup(self):
        for p in bridge.BACKUPS:
            self.assertEqual(bridge.target_status(p, "active"), "disabled")
        self.assertEqual(bridge.target_status(bridge.WPS, "active"), "active")
        self.assertEqual(bridge.target_status(bridge.WPS, "active", "disabled"), "disabled")

    def test_cas_requires_exact_snapshot_and_explicit_absence(self):
        old = {"token": SECRET}
        for expected in (None, "wrong", bridge.MISSING):
            with self.assertRaises(bridge.BridgeError):
                bridge.check_cas(old, expected, True)
        bridge.check_cas(old, bridge.auth_hash(old), True)
        bridge.check_cas(old, bridge.MISSING, False)
        bridge.check_cas(None, None, True)
        with self.assertRaises(bridge.BridgeError):
            bridge.check_cas(None, bridge.auth_hash(old), True)

    def test_older_known_credentials_refused_even_with_cas(self):
        old = {"token": "old", "uid": "u1", "updatedAt": T1}
        request = upsert_record(auth={"token": "new", "updatedAt": T0},
                                expected_auth_hash=bridge.auth_hash(old))
        with self.assertRaisesRegex(bridge.BridgeError, "stale_credentials"):
            bridge.merge_plan(request, old, "disabled")

    def test_credential_clock_does_not_use_expiry_or_row_time(self):
        self.assertEqual(bridge.credential_time(
            {"expires_at": T1, "probed_at": T1, "updated_at": T1}), 0)
        self.assertEqual(bridge.timestamp_ms(T1 / 1000), T1)
        self.assertEqual(bridge.timestamp_ms(float("nan")), 0)


class InventoryTests(unittest.TestCase):
    def test_inventory_hashes_original_auth_and_exposes_private_normalized_auth(self):
        row = account(auth={"session": SECRET}, credits_synced_at=datetime.now(timezone.utc),
                      balance_remain=12, updated_at=datetime.now(timezone.utc))
        result = bridge.inventory_record(row)
        self.assertEqual(result["auth"]["token"], SECRET)
        self.assertEqual(result["auth_hash"], bridge.auth_hash({"session": SECRET}))
        self.assertEqual(result["balance"], 12)
        self.assertEqual(result["credential_at"], 0)
        self.assertIsNone(result["signedToday"])

    def test_unobserved_default_zero_not_reported_as_real_balance(self):
        row = account(last_sync_at=datetime.now(timezone.utc))
        self.assertIsNone(bridge.inventory_record(row)["balance"])

    def test_signed_snapshot_handles_timezone_and_truncation(self):
        now = datetime(2026, 11, 9, 2, tzinfo=timezone.utc)
        schedule = Schedule(last_run_at=datetime(2026, 11, 8, 16, 30),
                            last_result=json.dumps({
                                "detail_truncated": True, "claimed": 999,
                                "items": [{"account_id": 1, "ok": True, "outcome": "done"},
                                          {"account_id": 2, "ok": False, "outcome": "failed"}]}))
        signed = bridge.signed_snapshot([schedule], now)
        self.assertEqual(signed[1]["signed_date"], "2026-11-09")
        self.assertTrue(signed[1]["signedToday"])
        self.assertNotIn(2, signed)
        self.assertNotIn(3, signed)
        stale = bridge.signed_snapshot([schedule], now + timedelta(days=1))
        self.assertIsNone(stale[1]["signedToday"])
        self.assertFalse(stale[1]["signed_known"])

    def test_malformed_snapshot_does_not_claim_success(self):
        self.assertEqual(bridge.signed_snapshot(
            [Schedule(last_run_at=datetime.now(), last_result="broken")]), {})

    def test_null_snapshot_items_are_unknown(self):
        self.assertEqual(bridge.signed_snapshot([Schedule(
            last_run_at=datetime.now(), last_result='{"items":null}')]), {})

    def test_inventory_filters_platforms_and_returns_rejections(self):
        store = Store([account(), account(platform="other", aid=2),
                       account(aid=3, auth={"uid": "different", "token": SECRET})])
        result = bridge.handle({"command": "inventory"}, backend(store))
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"], result["accounts"])
        self.assertEqual(result["rejected"], [{"id": 3, "status": "uid_mismatch"}])

    def test_disabled_and_cooldown_routing(self):
        disabled = bridge.inventory_record(account(status="disabled"))
        self.assertEqual(disabled["routing_state"], "disabled")
        cooling = bridge.inventory_record(account(
            cool_until=datetime.now(timezone.utc) + timedelta(hours=1)))
        self.assertEqual(cooling["routing_state"], "cooldown")


class TransactionTests(unittest.TestCase):
    def test_new_upsert_is_disabled_and_keeps_uid(self):
        store = Store()
        result = bridge.handle({"command": "upsert",
                                "accounts": [upsert_record(expected_auth_hash=None)]},
                               backend(store))
        self.assertTrue(result["ok"])
        row = store.rows[Account][0]
        self.assertEqual(row.status, "disabled")
        self.assertEqual(row.uid, "u1")
        self.assertEqual(store.begins, 1)
        self.assertEqual(store.commits, 1)

    def test_parent_batch_contract_and_source_identity_ignored(self):
        store = Store()
        result = bridge.handle({"command": "upsert", "accounts": [
            upsert_record(expected_auth_hash=None, primary="agent2api", source_id="agent-uuid"),
            upsert_record(uid="u2", expected_auth_hash="stale")]}, backend(store))
        self.assertEqual(result["results"], result["items"])
        created, rejected = result["results"]
        self.assertEqual(created["platform"], "loomy")
        self.assertEqual(created["uid"], "u1")
        self.assertIs(created["created"], True)
        self.assertEqual(created["id"], 1)
        self.assertEqual(rejected["uid"], "u2")
        self.assertEqual(rejected["platform"], "loomy")
        self.assertFalse(rejected["created"])
        self.assertIsNone(rejected["id"])
        self.assertFalse(rejected["ok"])

    def test_primary_balance_injection_updates_native_fields_and_inventory(self):
        original = account(balance_remain=99)
        store = Store([original])
        request = upsert_record(primary="agent2api", balance=12.75, balance_at=T1,
                                expected_auth_hash=bridge.auth_hash(json.loads(original.auth_json)))
        result = bridge.handle({"command": "upsert", "account": request}, backend(store))
        self.assertTrue(result["balanceChanged"])
        row = store.rows[Account][0]
        self.assertEqual(row.balance_remain, 12)  # native apply_quota casts to int
        self.assertEqual(bridge.timestamp_ms(row.balance_synced_at), T1)
        self.assertEqual(row.balance_synced_at, row.credits_synced_at)
        self.assertIsNone(row.credits_synced_at.tzinfo)  # native ORM uses UTC-naive
        self.assertEqual(bridge.inventory_record(row)["balance_at"], T1)

    def test_stale_or_nonfinite_balance_does_not_replace_native_snapshot(self):
        at = datetime.fromtimestamp(T1 / 1000, timezone.utc).replace(tzinfo=None)
        for value, timestamp in ((7, T0), (7, T1), (float("nan"), T1 + 1000),
                                 (float("inf"), T1 + 1000), (True, T1 + 1000),
                                 (None, T1 + 1000), (7, float("inf"))):
            row = account(balance_remain=99, credits_synced_at=at)
            self.assertFalse(bridge.inject_balance(
                row, {"primary": "agent2api", "balance": value, "balance_at": timestamp}))
            self.assertEqual(row.balance_remain, 99)
            self.assertEqual(row.credits_synced_at, at)

    def test_balance_injection_requires_agent_primary_backup_platform(self):
        for row, primary in ((account(), None), (account(), "mirai"),
                             (account(platform=bridge.WPS), "agent2api")):
            self.assertFalse(bridge.inject_balance(
                row, {"primary": primary, "balance": 11, "balance_at": T1}))
        for platform in bridge.BACKUPS:
            row = account(platform=platform)
            self.assertTrue(bridge.inject_balance(
                row, {"primary": "agent2api", "balance": 0, "balance_at": T1}))
            self.assertEqual(row.balance_remain, 0)

    def test_conflict_rolls_back_without_status_or_auth_change(self):
        original = account()
        store = Store([original])
        result = bridge.handle({"command": "upsert", "account":
                                upsert_record(expected_auth_hash="stale")}, backend(store))
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(store.rows[Account][0].__dict__, original.__dict__)
        self.assertEqual(store.rollbacks, 1)

    def test_matching_cas_preserves_balance_cooldown_and_custom_auth(self):
        original = account(auth={"uid": "u1", "token": "old", "password": "pw"},
                           balance_remain=99, last_err_msg="existing-error",
                           cool_until=datetime(2030, 1, 1))
        store = Store([original])
        result = bridge.handle({"command": "upsert", "account": upsert_record(),
                                "expected_auth_hash": bridge.auth_hash(
                                    json.loads(original.auth_json))}, backend(store))
        self.assertTrue(result["ok"])
        row = store.rows[Account][0]
        self.assertEqual(row.balance_remain, 99)
        self.assertEqual(row.last_err_msg, "existing-error")
        self.assertEqual(row.cool_until, original.cool_until)
        self.assertEqual(json.loads(row.auth_json)["password"], "pw")
        self.assertEqual(row.status, "active")

    def test_batch_has_independent_transactions_and_does_not_echo_secrets(self):
        store = Store()
        result = bridge.handle({"command": "upsert", "accounts": [
            upsert_record(expected_auth_hash=None),
            upsert_record(uid="u2", auth={"token": SECRET}, expected_auth_hash="bad")]},
            backend(store))
        self.assertFalse(result["ok"])
        self.assertEqual(len(store.rows[Account]), 1)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_duplicate_identity_fails_closed(self):
        store = Store([account(aid=1), account(aid=2)])
        result = bridge.handle({"command": "upsert", "account": upsert_record()}, backend(store))
        self.assertEqual(result["status"], "ambiguous_identity")
        self.assertEqual(store.commits, 0)

    def test_commit_failure_is_rolled_back_and_sanitized(self):
        store = Store()
        store.fail_commit = True
        result = bridge.handle({"command": "upsert", "account": upsert_record()}, backend(store))
        self.assertEqual(result["status"], "internal_error")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(store.rows[Account], [])

    def test_wps_disabled_target_stays_disabled(self):
        original = account(platform=bridge.WPS, status="disabled")
        store = Store([original])
        record = upsert_record(platform=bridge.WPS, auth={"cookie": "new-cookie"},
                               expected_auth_hash=bridge.auth_hash(json.loads(original.auth_json)))
        result = bridge.handle({"command": "upsert", "account": record}, backend(store))
        self.assertTrue(result["ok"])
        self.assertEqual(store.rows[Account][0].status, "disabled")


class TaskTests(unittest.TestCase):
    def test_loomy_backup_credential_requires_cas_and_identity(self):
        a=account('loomy',status='disabled',auth={'uid':'u1','token':'old','loginid':'phone','password':'private'})
        store=Store([a]);calls=[]
        def executor(action,db,row):
            calls.append(action)
            raw=json.loads(row.auth_json);raw['token']='new';row.auth_json=json.dumps(raw);db.commit()
            return {'ok':True}
        native=backend(store,executor)
        base={'command':'task','account_id':'1','action':'credential','backup_maintenance':True,'uid':'u1'}
        self.assertEqual(native.task(base)['status'],'conflict')
        result=native.task({**base,'expected_auth_hash':bridge.auth_hash(json.loads(a.auth_json))})
        self.assertTrue(result['ok']);self.assertTrue(result['credentialChanged'])
        self.assertEqual(store.rows[Account][0].status,'disabled');self.assertEqual(calls,['credential'])

    def call(self, row, action, executor=None, **extra):
        store = Store([row])
        return bridge.handle({"command": "task", "account_id": row.id,
                              "action": action, **extra}, backend(store, executor))

    def test_disabled_wps_never_runs_native(self):
        def forbidden(*args):
            self.fail("native executor called")
        result = self.call(account(platform=bridge.WPS, status="disabled"),
                           "balance", forbidden)
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(set(result), FIELDS)

    def test_account_id_positive_numeric_string_supported(self):
        def native(action, db, row):
            return {"ok": True}
        row = account(platform=bridge.WPS)
        result = bridge.handle({"command": "task", "account_id": "1", "action": "balance"},
                               backend(Store([row]), native))
        self.assertEqual(result["status"], "ok")
        for invalid in ("0", "-1", "1.0", " 1 ", True, 1.5, "1;drop", "9" * 20):
            result = bridge.handle({"command": "task", "account_id": invalid, "action": "balance"},
                                   backend(Store([row]), native))
            self.assertEqual(result["status"], "invalid_account_id")

    def test_backup_codearts_and_unsupported_actions_do_not_run_native(self):
        def forbidden(*args):
            self.fail("native executor called")
        for platform, action in (("codearts", "balance"), (bridge.WPS, "credential"),
                                 (bridge.WPS, "ban_recheck"), (bridge.WPS, "invite")):
            result = self.call(account(platform=platform), action, forbidden)
            self.assertEqual(result["status"], "unsupported")

    def test_single_account_success_is_sanitized(self):
        def native(action, db, row):
            row.balance_remain = 17
            row.credits_synced_at = datetime.now(timezone.utc)
            db.commit()
            return {"ok": True, "outcome": "claimed", "detail": SECRET, "token": SECRET}
        result = self.call(account(platform=bridge.WPS), "checkin", native)
        self.assertTrue(result["ok"])
        self.assertTrue(result["signed"])
        self.assertEqual(result["balance"], 17)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(set(result), FIELDS)

    def test_task_error_and_exception_never_leak(self):
        def native(*args):
            return {"ok": False, "error": {"kind": "auth", "message": SECRET}}
        result = self.call(account(platform=bridge.WPS), "balance", native)
        self.assertEqual(result["status"], "needs_login")
        self.assertNotIn(SECRET, json.dumps(result))
        def raises(*args):
            raise RuntimeError(SECRET)
        result = self.call(account(platform=bridge.WPS), "balance", raises)
        self.assertEqual(result["status"], "failed")
        self.assertNotIn(SECRET, json.dumps(result))

    def test_task_cas_and_cooldown_prevent_calls(self):
        def forbidden(*args):
            self.fail("native executor called")
        result = self.call(account(platform=bridge.WPS), "balance", forbidden,
                           expected_auth_hash="stale")
        self.assertEqual(result["status"], "conflict")
        row = account(platform=bridge.WPS,
                      breaker_until=datetime.now(timezone.utc) + timedelta(hours=1))
        self.assertEqual(self.call(row, "checkin", forbidden)["status"], "cooldown")

    def test_native_checkin_explicitly_disables_one_time_claims(self):
        calls = []
        fake = SimpleNamespace(checkin_account=lambda *args, **kw:
                               calls.append((args, kw)) or {"ok": True})
        with patch.object(bridge.importlib, "import_module", return_value=fake) as load:
            bridge.native_wps("checkin", "db", "account")
        self.assertEqual(calls, [(("db", "account"), {"claim_one_time": False})])
        self.assertEqual(load.call_args.args[0],
                         "admin.platform.wps_lingxi.services.checkin")

    def test_native_keepalive_calls_single_account_quota(self):
        calls = []
        fake = SimpleNamespace(sync_quota=lambda *args: calls.append(args) or {"ok": True})
        with patch.object(bridge.importlib, "import_module", return_value=fake):
            bridge.native_wps("keepalive", "db", "account")
        self.assertEqual(calls, [("db", "account")])

    def test_activity_preserves_deduplication_and_probability(self):
        calls = []
        fake = SimpleNamespace(
            _enabled=lambda: True, _active_today=lambda *args: True,
            _probability=lambda: 0.5,
            humanize=SimpleNamespace(human_probability=lambda p: False),
            activate_account=lambda *args: calls.append(args) or {"ok": True})
        with patch.object(bridge.importlib, "import_module", return_value=fake):
            self.assertEqual(bridge.native_wps("activity", 1, 2)["bridge_skip"], "already_active")
            fake._active_today = lambda *args: False
            self.assertEqual(bridge.native_wps("activity", 1, 2)["bridge_skip"], "probability_skip")
            fake.humanize.human_probability = lambda p: True
            self.assertTrue(bridge.native_wps("activity", 1, 2)["ok"])
        self.assertEqual(calls, [(1, 2)])


class OwnershipAndProtocolTests(unittest.TestCase):
    def test_ownership_only_changes_enabled_of_owned_schedules(self):
        schedules = [
            Schedule(id=1), Schedule(id=2, task="wps_lingxi_activity"),
            Schedule(id=3, task="wps_lingxi_ban_recheck"),
            Schedule(id=4, platform="loomy", task="loomy_onboarding"),
            Schedule(id=5, platform="workbuddy", task="daily_checkin"),
            Schedule(id=6, platform="raccoon", enabled=0),
            Schedule(id=7, task="unknown_new_runner")]
        store = Store(schedules=schedules)
        result = bridge.handle({"command": "take_ownership"}, backend(store))
        self.assertEqual(result["disabled_ids"], [4])
        self.assertEqual([r["id"] for r in result["left_native"]], [1, 2, 3, 7])
        self.assertFalse(result["ownership_complete"])
        self.assertNotIn(SECRET, json.dumps(result))
        for before, after in zip(schedules, store.rows[Schedule]):
            a, b = dict(before.__dict__), dict(after.__dict__)
            a.pop("enabled"); b.pop("enabled")
            self.assertEqual(a, b)
        self.assertEqual(store.rows[Schedule][4].enabled, 1)
        repeated = bridge.handle({"command": "take_ownership"}, backend(store))
        self.assertEqual(repeated["disabled_ids"], [])

    def test_invalid_command_does_not_import_native(self):
        with patch.object(bridge, "NativeBackend", side_effect=AssertionError):
            self.assertEqual(bridge.handle({"command": SECRET})["status"], "invalid_command")

    def test_quiet_native_hides_stdout_stderr_and_restores_logger(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        prior = logging.root.manager.disable
        with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
            with bridge.quiet_native():
                print(SECRET)
                print(SECRET, file=sys.stderr)
                logging.error(SECRET)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(logging.root.manager.disable, prior)

    def test_cli_malformed_json_does_not_echo_input_or_traceback(self):
        process = subprocess.run(
            [sys.executable, "-B", str(Path(bridge.__file__))],
            input=SECRET, capture_output=True, text=True, check=False)
        self.assertEqual(process.returncode, 1)
        result = json.loads(process.stdout)
        self.assertFalse(result["ok"])
        self.assertEqual(process.stderr, "")
        self.assertNotIn(SECRET, process.stdout)

    def test_cli_unknown_command_one_json_no_native_import(self):
        process = subprocess.run(
            [sys.executable, "-B", str(Path(bridge.__file__))],
            input=json.dumps({"command": "not-supported"}), capture_output=True,
            text=True, check=False)
        self.assertEqual(json.loads(process.stdout)["status"], "invalid_command")
        self.assertEqual(process.stderr, "")


if __name__ == "__main__":
    unittest.main()

