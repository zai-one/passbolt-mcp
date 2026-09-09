"""Trusted operator approval CLI; acceptance is never an MCP tool."""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict
from uuid import UUID

from zai_passbolt.config import ServiceConfig
from zai_passbolt.onboarding import load_config
from zai_passbolt.runtime import Runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("approval_id", type=UUID)
    parser.add_argument("--accept", action="store_true")
    parser.add_argument("--principal")
    parser.add_argument("--request-hash")
    parser.add_argument("--config", help="Operator JSON settings")
    args = parser.parse_args()
    if args.accept and (not args.principal or not args.request_hash):
        parser.error("acceptance requires the reviewed principal and exact request hash")
    runtime = None
    try:
        load_config(args.config)
        runtime = Runtime(ServiceConfig.from_env(), "stdio")
        if args.accept:
            result = runtime.store.transition_approval(
                args.approval_id, status="accepted", actor=args.principal, digest=args.request_hash
            )
            print(json.dumps({"accepted": result}))
            if not result:
                raise SystemExit(1)
        else:
            record = asyncio.run(runtime.store.get_approval(args.approval_id))
            print(json.dumps(asdict(record) if record else None, default=str))
    except (ValueError, OSError, PermissionError):
        parser.exit(2, "configuration, custody or approval mismatch; check local files\n")
    finally:
        if runtime:
            runtime.close()


if __name__ == "__main__":
    main()
