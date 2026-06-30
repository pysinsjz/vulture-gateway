#!/usr/bin/env python3
"""
litellm team 签发 + /v1/models 展开冒烟（ADR-0016 workaround 回归探针）。

直接走 litellm 管理面，不经网关——验证「按 team_id 签发 + 省略 models 字段」这条 ADR-0016
核心 workaround 在当前 litellm 版本仍然有效（litellm bug #3275 历史阴影）。

链路：
  /team/list  (Master Key)        → 找 default_team_alias 对应 team_id
       → /key/generate (Master Key, team_id, 省略 models) → 签出 sk-...
       → /v1/models (新 key)                              → 断言返回 team 真实模型 id
                                                            **不是 ["all-team-models"] 占位**
       → /key/delete (Master Key)                         → 清理

任一步失败 → 退出码非 0。何时跑：
  - litellm 版本升级后（验证 workaround 未被官方变更打破）
  - 部署到新环境后（确认 team 配置 + master key 联通）
  - 排障「用户拉模型清单异常」时（隔离是网关侧还是 litellm 侧）

环境变量：
  LITELLM_BASE      litellm 基址，默认 http://47.110.248.193:4000
  LITELLM_MASTER    litellm Master Key（默认填 dev 实例占位 key）
  TEAM_ALIAS        要验证的 team 别名，默认 team-pro
"""

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("LITELLM_BASE", "http://47.110.248.193:4000")
MK = os.environ.get(
    "LITELLM_MASTER",
    "sk-2e2c4c66bbc2dbcae046637d06312630f1c8367bdab4fee4701712f088ab391b",
)
TEAM_ALIAS = os.environ.get("TEAM_ALIAS", "team-pro")
TEST_USER = "smoke-team-vkey-script"

PLACEHOLDER_BUG_VALUE = "all-team-models"  # litellm bug #3275 占位


def call(method: str, path: str, auth: str, body=None):
    url = BASE.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {auth}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()
        print(f"  HTTP {e.code}: {body_text}")
        return e.code, None


def cleanup(key: str):
    status, _ = call("POST", "/key/delete", MK, {"keys": [key]})
    print(f"  [cleanup] /key/delete status={status}")


def main() -> int:
    print(f"[1/4] GET /team/list @ {BASE}")
    status, teams = call("GET", "/team/list", MK)
    if status != 200 or not teams:
        print(f"  ✗ /team/list 失败 status={status}")
        return 1

    if isinstance(teams, dict):
        team_list = teams.get("data") or teams.get("teams") or []
    else:
        team_list = teams
    print(f"  找到 {len(team_list)} 个 team")
    for t in team_list[:10]:
        alias = t.get("team_alias") or t.get("alias")
        tid = t.get("team_id") or t.get("id")
        print(f"    - {alias} = {tid}")

    target = next(
        (t for t in team_list if (t.get("team_alias") or t.get("alias")) == TEAM_ALIAS),
        None,
    )
    if not target:
        print(f"  ✗ 未找到 alias={TEAM_ALIAS!r} 的 team（需在 litellm 后台先建好）")
        return 2
    team_id = target.get("team_id") or target.get("id")
    team_models = target.get("models") or []
    print(f"  ✓ alias={TEAM_ALIAS} → team_id={team_id}")
    print(f"  team 配置的 models = {team_models}")

    print(f"\n[2/4] POST /key/generate (team_id={team_id}, 不带 models)")
    status, gen = call(
        "POST",
        "/key/generate",
        MK,
        {
            "key_alias": f"smoke-{TEST_USER}",
            "user_id": TEST_USER,
            "team_id": team_id,
            "max_budget": 9999999,
        },
    )
    if status != 200 or not gen:
        print(f"  ✗ 签发失败 status={status}")
        return 3
    new_key = gen.get("key")
    print(f"  ✓ 签出 key={new_key[:24]}...")
    print(f"  响应里 models 字段 = {gen.get('models')}  （ADR-0016：应为空列表或缺失）")

    print(f"\n[3/4] GET /v1/models 用新 key 拉清单")
    status, ml = call("GET", "/v1/models", new_key)
    if status != 200 or not isinstance(ml, dict):
        print(f"  ✗ /v1/models 失败 status={status} body={ml}")
        cleanup(new_key)
        return 4
    models_data = ml.get("data") if isinstance(ml, dict) else None
    if not isinstance(models_data, list):
        print(f"  ✗ /v1/models 响应缺 data 数组: {ml}")
        cleanup(new_key)
        return 4
    ids = [m.get("id") for m in models_data]
    print(f"  返回 {len(ids)} 个模型: {ids}")

    if ids == [PLACEHOLDER_BUG_VALUE]:
        print(f"  ✗ 命中 litellm bug #3275：仅返回占位 ['{PLACEHOLDER_BUG_VALUE}']，未展开真实模型")
        print(f"     workaround 失效，确认 litellm 版本变更或 team 配置异常")
        cleanup(new_key)
        return 5
    if PLACEHOLDER_BUG_VALUE in ids:
        print(f"  ⚠ 警告：返回里混进了 '{PLACEHOLDER_BUG_VALUE}' 字面值（异常但未完全命中 bug）")
    print(f"  ✓ /v1/models 正确展开为 team 真实模型清单")

    print(f"\n[4/4] /key/delete 清理")
    cleanup(new_key)
    print(f"\n=== PASS: ADR-0016「team_id + 省略 models」workaround 在 {BASE} 仍然生效 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
