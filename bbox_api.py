#!/usr/bin/env python3
import ipaddress
import json
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BboxAPI:
    def __init__(self, host: str, password: str, verify_ssl: bool = False, timeout: int = 10):
        self.host = host.rstrip("/")
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()

    def _url(self, path: str) -> str:
        return f"{self.host}{path}"

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        response = self.session.request(
            method=method,
            url=self._url(path),
            verify=self.verify_ssl,
            timeout=self.timeout,
            **kwargs,
        )
        response.raise_for_status()
        return response

    def login(self) -> None:
        self._request(
            "POST",
            "/api/v1/login",
            data={"password": self.password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def get_token(self) -> str:
        data = self._request("GET", "/api/v1/device/token").json()

        if isinstance(data, list):
            if not data:
                raise RuntimeError("Réponse token vide")
            data = data[0]

        if isinstance(data, dict):
            token = data.get("device", {}).get("token")
            if token:
                return token

        raise RuntimeError(f"Token introuvable: {json.dumps(data, indent=2, ensure_ascii=False)}")

    def list_rules(self, token: str) -> list[dict[str, Any]]:
        data = self._request("GET", "/api/v1/firewall/rules", params={"btoken": token}).json()

        rules: list[dict[str, Any]] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                nested_rules = node.get("rules")
                if isinstance(nested_rules, list):
                    rules.extend(item for item in nested_rules if isinstance(item, dict) and "id" in item)

                for value in node.values():
                    walk(value)
                return

            if isinstance(node, list):
                for item in node:
                    walk(item)

        walk(data)

        if not rules:
            raise RuntimeError(
                "Format de réponse inattendu pour firewall/rules: "
                f"{json.dumps(data, indent=2, ensure_ascii=False)}"
            )

        unique: dict[Any, dict[str, Any]] = {}
        for rule in rules:
            unique[rule["id"]] = rule
        return list(unique.values())

    def add_rule(self, token: str, srcip: str, description: str = "ban-rule") -> dict[str, Any]:
        self.validate_ipv4(srcip)

        payload = {
            "enable": "1",
            "description": description,
            "srcipnot": "0",
            "srcip": srcip,
            "srcports": "",
            "dstipnot": "0",
            "dstip": "",
            "dstports": "",
            "protocols": "tcp,udp",
            "action": "Drop",
            "ipprotocol": "IPv4",
        }

        response = self._request(
            "POST",
            "/api/v1/firewall/rules",
            params={"btoken": token},
            data=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
            },
        )

        return {
            "status_code": response.status_code,
            "location": response.headers.get("Location", ""),
            "text": response.text,
        }

    def delete_rule_by_id(self, rule_id: int) -> dict[str, Any]:
        response = self._request("DELETE", f"/api/v1/firewall/rules/{rule_id}")
        return {"status_code": response.status_code, "text": response.text}

    def find_rules_by_srcip(self, token: str, srcip: str) -> list[dict[str, Any]]:
        self.validate_ipv4(srcip)
        rules = self.list_rules(token)

        return [
            rule
            for rule in rules
            if str(rule.get("srcip", "")).strip() == srcip
            and str(rule.get("action", "")).strip() == "Drop"
            and str(rule.get("protocols", "")).strip() == "tcp,udp"
            and str(rule.get("ipprotocol", "")).strip() == "IPv4"
        ]

    @staticmethod
    def validate_ipv4(ip: str) -> None:
        try:
            ipaddress.IPv4Address(ip)
        except Exception as exc:
            raise ValueError(f"IPv4 invalide: {ip}") from exc
