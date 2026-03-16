#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable

import jwt
from flask import Flask, jsonify, request

from bbox_api import BboxAPI
from config import Config

app = Flask(__name__)


def json_error(message: str, status: int):
    return jsonify({"error": message}), status


def json_ok(payload: dict[str, Any], status: int = 200):
    return jsonify(payload), status


def make_bbox() -> BboxAPI:
    return BboxAPI(
        host=Config.BBOX_HOST,
        password=Config.BBOX_PASSWORD,
        verify_ssl=Config.BBOX_VERIFY_SSL,
    )


def generate_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=Config.JWT_EXP_MINUTES),
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")


def require_auth(fn: Callable[..., Any]):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return json_error("Authorization Bearer token requis", 401)

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return json_error("Token vide", 401)

        try:
            request.jwt_payload = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return json_error("Token expiré", 401)
        except jwt.InvalidTokenError:
            return json_error("Token invalide", 401)

        return fn(*args, **kwargs)

    return wrapper


@app.route("/health", methods=["GET"])
def health():
    return json_ok({"status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))

    if username != Config.APP_USERNAME or password != Config.APP_PASSWORD:
        return json_error("Identifiants invalides", 401)

    token = generate_token(username)
    return json_ok(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in_seconds": Config.JWT_EXP_MINUTES * 60,
        }
    )


@app.route("/rules", methods=["GET"])
@require_auth
def rules():
    try:
        bbox = make_bbox()
        bbox.login()
        btoken = bbox.get_token()
        return json_ok({"rules": bbox.list_rules(btoken)})
    except Exception as exc:
        return json_error(str(exc), 500)


@app.route("/ban", methods=["POST"])
@require_auth
def ban():
    payload = request.get_json(silent=True) or {}
    srcip = str(payload.get("srcip", "")).strip()
    description = str(payload.get("description", "")).strip() or f"ban-{srcip}"

    if not srcip:
        return json_error("srcip requis", 400)

    try:
        bbox = make_bbox()
        bbox.login()
        btoken = bbox.get_token()

        existing = bbox.find_rules_by_srcip(btoken, srcip)
        if existing:
            return json_ok(
                {
                    "message": "Une règle existe déjà pour cette IP",
                    "srcip": srcip,
                    "rules": existing,
                }
            )

        result = bbox.add_rule(token=btoken, srcip=srcip, description=description)
        updated_rules = bbox.find_rules_by_srcip(btoken, srcip)

        return json_ok(
            {
                "message": "IP bannie",
                "srcip": srcip,
                "description": description,
                "result": result,
                "rules": updated_rules,
            },
            201,
        )

    except Exception as exc:
        return json_error(str(exc), 500)


@app.route("/unban", methods=["POST"])
@require_auth
def unban():
    payload = request.get_json(silent=True) or {}
    srcip = str(payload.get("srcip", "")).strip()

    if not srcip:
        return json_error("srcip requis", 400)

    try:
        bbox = make_bbox()
        bbox.login()
        btoken = bbox.get_token()

        matches = bbox.find_rules_by_srcip(btoken, srcip)
        if not matches:
            return json_error("Aucune règle trouvée pour cette IP", 404)

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
                    "dstip": rule.get("dstip", ""),
                    "result": bbox.delete_rule_by_id(int(rule_id)),
                }
            )

        return json_ok({"message": "IP débannie", "srcip": srcip, "deleted": deleted})

    except Exception as exc:
        return json_error(str(exc), 500)


@app.route("/delete-rule/<int:rule_id>", methods=["DELETE"])
@require_auth
def delete_rule(rule_id: int):
    try:
        bbox = make_bbox()
        bbox.login()
        result = bbox.delete_rule_by_id(rule_id)
        return json_ok({"message": "Règle supprimée", "id": rule_id, "result": result})
    except Exception as exc:
        return json_error(str(exc), 500)


if __name__ == "__main__":
    app.run(host=Config.API_HOST, port=Config.API_PORT, debug=Config.DEBUG)
