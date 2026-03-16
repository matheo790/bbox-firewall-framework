#!/usr/bin/env python3
import argparse
import json
import sys

from bbox_api import BboxAPI


def output(payload: dict, code: int = 0) -> int:
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lister les règles firewall Bbox")
    parser.add_argument("--host", default="https://mabbox.bytel.fr", help="URL de la Bbox")
    parser.add_argument("--password", required=True, help="Mot de passe admin Bbox")
    parser.add_argument("--verify-ssl", action="store_true", help="Activer la vérification SSL")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    api = BboxAPI(args.host, args.password, verify_ssl=args.verify_ssl)

    try:
        api.login()
        token = api.get_token()
        rules = api.list_rules(token)
        return output({"count": len(rules), "rules": rules})
    except Exception as exc:
        return output({"error": str(exc)}, 1)


if __name__ == "__main__":
    sys.exit(main())
