"""Bounded retention maintenance; never remove active work or trust records."""

import asyncio
import logging
import sqlite3
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from . import store
from .auth import admin

router = APIRouter(prefix="/api/v1/settings/retention")
LOCK = threading.Lock()
DEFAULTS = {"audit_days": 180, "diagnostic_days": 30, "scan_days": 30, "zabbix_days": 7}


class RetentionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    audit_days: int = Field(default=180, ge=7, le=3650)
    diagnostic_days: int = Field(default=30, ge=1, le=3650)
    scan_days: int = Field(default=30, ge=1, le=3650)
    zabbix_days: int = Field(default=7, ge=1, le=3650)


def config():
    return {
        key: int(store.setting("retention_" + key) or default)
        for key, default in DEFAULTS.items()
    }


def cleanup():
    if not LOCK.acquire(blocking=False):
        return {"busy": True}
    try:
        days, counts = config(), {}
        with store.db() as c:
            for table, condition, value in (
                ("audit", "created_at < datetime('now',?)", days["audit_days"]),
                (
                    "diagnostic_jobs",
                    "status NOT IN ('queued','running') AND completed_at < datetime('now',?)",
                    days["diagnostic_days"],
                ),
                (
                    "diagnostic_batches",
                    "created_at < datetime('now',?) AND NOT EXISTS (SELECT 1 FROM diagnostic_jobs WHERE batch_id=diagnostic_batches.id)",
                    days["diagnostic_days"],
                ),
                (
                    "scan_results",
                    "batch_id IN (SELECT id FROM scan_batches WHERE status!='running' AND created_at < datetime('now',?))",
                    days["scan_days"],
                ),
                (
                    "scan_batches",
                    "status!='running' AND created_at < datetime('now',?)",
                    days["scan_days"],
                ),
                (
                    "zabbix_sync_runs",
                    "status NOT IN ('queued','running') AND completed_at < datetime('now',?)",
                    days["zabbix_days"],
                ),
            ):
                counts[table] = c.execute(
                    "DELETE FROM " + table + " WHERE " + condition, (f"-{value} days",)
                ).rowcount
        # VACUUM is outside a transaction. Limit it to once a day and only after
        # deletion; SQLite safely serializes it with concurrent writers.
        with store.db() as c:
            due = c.execute(
                "SELECT ? < datetime('now','-1 day')",
                (store.setting("retention_vacuum_at") or "",),
            ).fetchone()[0]
        if sum(counts.values()) and due:
            try:
                with store.db() as c:
                    c.execute("VACUUM")
                    timestamp = c.execute("SELECT CURRENT_TIMESTAMP").fetchone()[0]
                store.save_settings({"retention_vacuum_at": timestamp})
            except sqlite3.OperationalError:
                counts["vacuum_deferred"] = True
        store.save_settings(
            {"retention_last_cleanup": datetime.now(timezone.utc).isoformat()}
        )
        return counts
    finally:
        LOCK.release()


async def periodic():
    # Run after startup, then hourly; a busy database retries next time.
    await asyncio.sleep(1)
    while True:
        try:
            await asyncio.to_thread(cleanup)
        except Exception:
            logging.getLogger(__name__).exception("Retention maintenance failed")
        await asyncio.sleep(3600)


@router.get("")
def get(actor=Depends(admin)):
    return {
        **config(),
        "last_cleanup": store.setting("retention_last_cleanup"),
        "last_vacuum": store.setting("retention_vacuum_at"),
    }


@router.put("")
def save(body: RetentionIn, actor=Depends(admin)):
    store.save_settings(
        {"retention_" + key: str(value) for key, value in body.model_dump().items()}
    )
    store.audit(actor, "retention_update", "settings", "success")
    return {"ok": True}


@router.post("/cleanup")
def run(actor=Depends(admin)):
    result = cleanup()
    if result.get("busy"):
        # Another cleanup holds the lock; this request deleted nothing.
        store.audit(actor, "retention_cleanup", "history", "failed", "busy")
    else:
        store.audit(actor, "retention_cleanup", "history", "success")
    return result
