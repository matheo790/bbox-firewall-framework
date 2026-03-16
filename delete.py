#!/usr/bin/env python3
import argparse
import json
import sys

from bbox_api import BboxAPI


def output(payload: dict, code: int = 0) -> int:
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Supprimer une règle firewall Bbox")
    parser.add_argument("--host", default="https://mabbox.bytel.fr", help="URL de la Bbox")
    parser.add_argument("--password", required=True, help="Mot de passe admin Bbox")
    parser.add_argument("--id", type=int, help="ID exact de la règle à supprimer")
    parser.add_argument("--srcip", help="Supprimer toutes les règles de cette IP source")
    parser.add_argument("--verify-ssl", action="store_true", help="Activer la vérification SSL")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.id is None and not args.srcip:
        return output({"error": "Il faut fournir --id ou --srcip"}, 1)

    api = BboxAPI(args.host, args.password, verify_ssl=args.verify_ssl)

    try:
        api.login()

        if args.id is not None:
            result = api.delete_rule_by_id(args.id)
            return output({"message": "Règle supprimée", "id": args.id, "result": result})

        token = api.get_token()
        matches = api.find_rules_by_srcip(token, args.srcip)

        if not matches:
            return output({"message": "Aucune règle trouvée", "srcip": args.srcip, "deleted": []})

        deleted = []
        for rule in matches:
            rule_id = rule.get("id")
            if rule_id is None:
                continue
            deleted.append(
                {
                    "id": rule_id,
                    "description": rule.get("description", ""),
                    "srcip": rule.get("srcip", ""),
                    "result": api.delete_rule_by_id(int(rule_id)),
                }
            )

        return output({"message": "Règle(s) supprimée(s)", "srcip": args.srcip, "deleted": deleted})
    except Exception as exc:
        return output({"error": str(exc)}, 1)


if __name__ == "__main__":
    sys.exit(main())
