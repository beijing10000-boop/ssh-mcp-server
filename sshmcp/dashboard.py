"""Admin overview derived from persisted facts; findings remain encrypted at rest."""

import json
import time

from . import __version__, diagnostics, observations, store


def snapshot():
    now = int(time.time())
    with store.db() as c:
        funnel = dict(
            c.execute("""SELECT COUNT(*) AS registered,
          COALESCE(SUM(asset_type='linux' AND enabled=1),0) AS eligible,
          COALESCE(SUM(asset_type='linux' AND enabled=1 AND credential_id IS NOT NULL),0) AS credential_bound,
          COALESCE(SUM(asset_type='linux' AND enabled=1 AND credential_id IS NOT NULL AND host_key!=''),0) AS key_verified,
          COALESCE(SUM(asset_type='linux' AND enabled=1 AND credential_id IS NOT NULL AND host_key!='' AND last_status='success'),0) AS tested
          FROM hosts""").fetchone()
        )
        queue = dict(
            c.execute(
                "SELECT status,COUNT(*) FROM diagnostic_jobs WHERE status IN ('queued','running') GROUP BY status"
            ).fetchall()
        )
        counts = dict(
            c.execute(
                "SELECT status,COUNT(*) FROM diagnostic_jobs WHERE completed_at>=datetime('now','-1 day') AND action!='connection' AND status IN ('success','partial','failed') GROUP BY status"
            ).fetchall()
        )
        failures = [
            dict(r)
            for r in c.execute(
                "SELECT CASE WHEN error='' THEN '输出不完整、非零退出或采集能力不足' ELSE error END AS reason,COUNT(*) AS count FROM diagnostic_jobs WHERE completed_at>=datetime('now','-1 day') AND action!='connection' AND status IN ('failed','partial') GROUP BY reason ORDER BY count DESC LIMIT 5"
            )
        ]
        clients = [
            dict(r)
            for r in c.execute(
                "SELECT id,name,enabled,expires_at,last_used_at FROM mcp_clients ORDER BY enabled DESC,expires_at LIMIT 100"
            )
        ]
        active_clients = c.execute(
            "SELECT COUNT(*) FROM mcp_clients WHERE enabled=1 AND expires_at>? AND last_used_at>=datetime('now','-1 day')",
            (now,),
        ).fetchone()[0]
        expiring = c.execute(
            "SELECT COUNT(*) FROM mcp_clients WHERE enabled=1 AND expires_at>? AND expires_at<=?",
            (now, now + 7 * 86400),
        ).fetchone()[0]
        expired = c.execute(
            "SELECT COUNT(*) FROM mcp_clients WHERE enabled=1 AND expires_at<=?", (now,)
        ).fetchone()[0]
        recent = c.execute(
            "SELECT id,host_id,host_name,action,result,completed_at FROM diagnostic_jobs WHERE result IS NOT NULL AND action!='connection' AND completed_at>=datetime('now','-1 day') ORDER BY completed_at DESC,rowid DESC LIMIT 100"
        ).fetchall()
        groups = c.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        failed = c.execute(
            "SELECT COUNT(*) FROM audit WHERE outcome='failed' AND created_at>=datetime('now','-1 day')"
        ).fetchone()[0]
    findings = []
    seen = set()
    for row in recent:
        result = json.loads(store.unseal(row["result"]))
        if "findings" not in result and row["action"] in observations.PARSERS:
            result.update(
                observations.analyze(
                    row["action"],
                    result.get("output", ""),
                    status=result.get("status", "partial"),
                )
            )
        for finding in result.get("findings", []):
            key = (row["host_id"], finding.get("metric"))
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    **finding,
                    "job_id": row["id"],
                    "host_name": row["host_name"],
                    "action": row["action"],
                    "captured_at": row["completed_at"],
                }
            )
    findings.sort(key=lambda f: observations.LEVELS.get(f.get("level"), 3))
    total = sum(counts.values())
    return {
        "hosts": funnel["registered"],
        "ready": funnel["key_verified"],
        "verified": funnel["tested"],
        "groups": groups,
        "failed_actions": failed,
        "version": __version__,
        "funnel": funnel,
        "queue": {
            **diagnostics.slot_usage(),
            "queued": queue.get("queued", 0),
            "running": queue.get("running", 0),
            "pending": sum(queue.values()),
            "queue_capacity": 200,
        },
        "diagnostics_24h": {
            "total": total,
            "counts": counts,
            "success_rate": round(100 * counts.get("success", 0) / total, 1)
            if total
            else None,
            "failure_reasons": failures,
            "definition": "成功 /（成功 + 部分完成 + 失败）；按结束时间统计，不含取消、排队和连接测试，非主机健康率",
        },
        "mcp": {
            "active_24h": active_clients,
            "expiring_7d": expiring,
            "expired": expired,
            "items": clients,
        },
        "recent_findings": findings[:10],
        "findings_scope": "近 24 小时最近 100 条诊断，同主机同指标保留最新，最多 10 条，严重项优先",
    }
