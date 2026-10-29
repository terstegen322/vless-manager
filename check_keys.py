#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_keys.py — Фоновый чекер доступности VLESS-ключей для GitHub Gist.
Читает config.json, db.json и все *.txt файлы из указанного GitHub Gist,
проверяет TCP-пинг каждого уникального (host, port) с корректной поддержкой
IPv4, доменов и IPv6, обновляет счетчик silent_days в db.json, отсеивает
ключи, превысившие лимит дней неактивности конкретной папки, и отправляет
обновления обратно в Gist одним PATCH-запросом.
"""

import json
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

import requests

GIST_API_BASE = "https://api.github.com/gists"
TCP_TIMEOUT_SECONDS = 2.5
MAX_WORKERS = 25
DEFAULT_DAYS_FAVOURITES = 7
DEFAULT_DAYS_OTHER = 3


def parse_vless_uri(uri: str) -> Optional[Dict[str, str]]:
    """
    Парсит строку vless://uuid@host:port?...#remark
    Возвращает словарь с uuid, host (без квадратных скобок для сокета),
    port, dedup_key и исходным uri.
    """
    line = uri.strip()
    if not line.startswith("vless://"):
        return None

    try:
        parsed = urlparse(line)
        if parsed.scheme.lower() != "vless":
            return None

        uuid_val = unquote(parsed.username or "").strip()
        hostname = parsed.hostname
        port = parsed.port

        if not uuid_val or not hostname or not port:
            return None

        # urlparse.hostname автоматически убирает квадратные скобки [ ] у IPv6-адресов
        clean_host = hostname.strip().lower()
        dedup_key = f"{uuid_val.lower()}|{clean_host}|{port}"

        return {
            "uuid": uuid_val,
            "host": clean_host,
            "port": str(port),
            "dedup_key": dedup_key,
            "uri": line,
        }
    except Exception:
        return None


def check_tcp_endpoint(host: str, port: int, timeout: float = TCP_TIMEOUT_SECONDS) -> Tuple[bool, Optional[float]]:
    """
    Выполняет попытку TCP-соединения к (host, port) с поддержкой IPv4, DNS и IPv6.
    Возвращает (успех: bool, задержка_мс: float | None).
    """
    start_ts = datetime.now(timezone.utc)
    try:
        addr_info_list = socket.getaddrinfo(
            host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        for family, socktype, proto, _, sockaddr in addr_info_list:
            sock = None
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                elapsed_ms = (datetime.now(timezone.utc) - start_ts).total_seconds() * 1000.0
                return True, round(elapsed_ms, 1)
            except OSError:
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
        return False, None
    except Exception:
        return False, None


def parse_iso_utc(iso_str: Optional[str]) -> Optional[datetime]:
    """Безопасно парсит ISO-8601 строку в datetime с часовым поясом UTC."""
    if not iso_str:
        return None
    try:
        normalized = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def get_folder_max_days(folder_name: str, config_data: dict) -> int:
    """
    Возвращает максимальное число дней молчания (silent_days) для папки из config.json.
    """
    folders_section = config_data.get("folders", config_data)
    entry = folders_section.get(folder_name)

    if isinstance(entry, dict):
        val = entry.get("max_silent_days", entry.get("days"))
        if isinstance(val, (int, float)) and val >= 0:
            return int(val)
    elif isinstance(entry, (int, float)) and entry >= 0:
        return int(entry)

    if folder_name.lower() in ("favourites", "favorites"):
        return DEFAULT_DAYS_FAVOURITES
    return DEFAULT_DAYS_OTHER


def fetch_gist(gist_id: str, token: str) -> dict:
    """Загружает содержимое Gist через GitHub REST API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vless-gist-key-checker/1.0",
    }
    url = f"{GIST_API_BASE}/{gist_id}"
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    return response.json()


def patch_gist(gist_id: str, token: str, files_payload: Dict[str, Dict[str, str]]) -> None:
    """Обновляет измененные файлы в Gist одним PATCH-запросом."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vless-gist-key-checker/1.0",
    }
    url = f"{GIST_API_BASE}/{gist_id}"
    payload = {"files": files_payload}
    response = requests.patch(url, headers=headers, json=payload, timeout=30)
    response.raise_for_status()


def main() -> int:
    gist_token = os.environ.get("GIST_TOKEN", "").strip()
    gist_id = os.environ.get("GIST_ID", "").strip()

    if not gist_token or not gist_id:
        print("ОШИБКА: Переменные окружения GIST_TOKEN и GIST_ID обязательны.", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{now_iso}] Старт проверки VLESS-ключей в Gist {gist_id}...")

    try:
        gist_data = fetch_gist(gist_id, gist_token)
    except Exception as exc:
        print(f"ОШИБКА при чтении Gist: {exc}", file=sys.stderr)
        return 1

    files = gist_data.get("files", {})

    # 1. Читаем config.json
    config_data: dict = {}
    if "config.json" in files and files["config.json"].get("content"):
        try:
            config_data = json.loads(files["config.json"]["content"])
        except json.JSONDecodeError:
            print("ПРЕДУПРЕЖДЕНИЕ: Не удалось распарсить config.json, используются значения по умолчанию.")

    # 2. Читаем db.json
    db_data: Dict[str, dict] = {}
    if "db.json" in files and files["db.json"].get("content"):
        try:
            raw_db = json.loads(files["db.json"]["content"])
            if isinstance(raw_db, dict):
                db_data = raw_db
        except json.JSONDecodeError:
            print("ПРЕДУПРЕЖДЕНИЕ: Не удалось распарсить db.json, создается новая база.")

    # 3. Собираем все *.txt файлы (наборы ключей)
    txt_files: Dict[str, List[str]] = {}
    unique_endpoints: Set[Tuple[str, int]] = set()
    parsed_cache: Dict[str, dict] = {}

    for filename, file_obj in files.items():
        if not filename.endswith(".txt"):
            continue
        content = file_obj.get("content") or ""
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        txt_files[filename] = lines

        for line in lines:
            parsed = parse_vless_uri(line)
            if parsed:
                parsed_cache[line] = parsed
                unique_endpoints.add((parsed["host"], int(parsed["port"])))

    if not txt_files:
        print("В Gist не найдено ни одного *.txt файла с ключами. Завершение работы.")
        return 0

    print(f"Найдено папок (*.txt): {len(txt_files)} | Уникальных TCP-узлов (host:port): {len(unique_endpoints)}")

    # 4. Параллельная TCP-проверка всех уникальных (host, port)
    endpoint_results: Dict[Tuple[str, int], Tuple[bool, Optional[float]]] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ep = {
            executor.submit(check_tcp_endpoint, host, port): (host, port)
            for host, port in unique_endpoints
        }
        for future in as_completed(future_to_ep):
            ep = future_to_ep[future]
            try:
                ok, latency_ms = future.result()
                endpoint_results[ep] = (ok, latency_ms)
            except Exception:
                endpoint_results[ep] = (False, None)

    alive_count = sum(1 for ok, _ in endpoint_results.values() if ok)
    print(f"Результаты пинга узлов: {alive_count} онлайн / {len(unique_endpoints) - alive_count} оффлайн.")

    # 5. Обновляем статистику по каждому ключу в db_data
    seen_dedup_keys: Set[str] = set()
    for filename, lines in txt_files.items():
        for line in lines:
            parsed = parsed_cache.get(line)
            if not parsed:
                continue
            dedup_key = parsed["dedup_key"]
            if dedup_key in seen_dedup_keys:
                continue
            seen_dedup_keys.add(dedup_key)

            ep = (parsed["host"], int(parsed["port"]))
            is_alive, latency_ms = endpoint_results.get(ep, (False, None))

            record = db_data.get(dedup_key, {})
            first_added_str = record.get("first_added") or now_iso
            last_success_str = record.get("last_success_at")

            if is_alive:
                last_success_str = now_iso
                silent_days = 0
            else:
                reference_dt = parse_iso_utc(last_success_str) or parse_iso_utc(first_added_str) or now
                delta_days = max(0.0, (now - reference_dt).total_seconds() / 86400.0)
                prev_silent = int(record.get("silent_days", 0))
                computed_days = int(delta_days)
                if computed_days == 0 and last_success_str is None and prev_silent > 0:
                    silent_days = prev_silent + 1
                else:
                    silent_days = max(computed_days, 1 if delta_days >= 0.95 else computed_days)

            db_data[dedup_key] = {
                "host": parsed["host"],
                "port": int(parsed["port"]),
                "first_added": first_added_str,
                "last_success_at": last_success_str,
                "last_checked_at": now_iso,
                "last_status": "online" if is_alive else "offline",
                "last_latency_ms": latency_ms,
                "silent_days": silent_days,
            }

    # 6. Фильтрация ключей по папкам согласно порогам из config.json
    files_to_patch: Dict[str, Dict[str, str]] = {}
    total_removed = 0

    for filename, lines in txt_files.items():
        folder_name = filename[:-4]
        max_silent_days = get_folder_max_days(folder_name, config_data)

        kept_lines: List[str] = []
        seen_in_folder: Set[str] = set()
        removed_in_folder = 0

        for line in lines:
            parsed = parsed_cache.get(line)
            if not parsed:
                continue

            dedup_key = parsed["dedup_key"]
            if dedup_key in seen_in_folder:
                continue

            record = db_data.get(dedup_key, {})
            silent_days = int(record.get("silent_days", 0))

            if silent_days > max_silent_days:
                removed_in_folder += 1
                total_removed += 1
                print(
                    f"  [-] Удален из {filename}: {parsed['host']}:{parsed['port']} "
                    f"(silent_days={silent_days} > лимит={max_silent_days})"
                )
            else:
                kept_lines.append(line)
                seen_in_folder.add(dedup_key)

        new_content = "\n".join(kept_lines) + ("\n" if kept_lines else "# Нет активных ключей\n")
        old_content = files[filename].get("content") or ""

        if new_content != old_content:
            files_to_patch[filename] = {"content": new_content}

        print(
            f"  [*] Папка '{folder_name}' (лимит {max_silent_days} дн.): "
            f"оставлено {len(kept_lines)}, удалено {removed_in_folder}."
        )

    # 7. Сохраняем обновленный db.json
    new_db_content = json.dumps(db_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    old_db_content = (files.get("db.json") or {}).get("content") or ""
    if new_db_content != old_db_content:
        files_to_patch["db.json"] = {"content": new_db_content}

    # 8. Отправляем один PATCH-запрос в GitHub Gist
    if files_to_patch:
        try:
            patch_gist(gist_id, gist_token, files_to_patch)
            print(
                f"УСПЕХ: Обновлено файлов в Gist: {len(files_to_patch)} "
                f"(всего отсеяно мертвых ключей: {total_removed})."
            )
        except Exception as exc:
            print(f"ОШИБКА при обновлении Gist: {exc}", file=sys.stderr)
            return 1
    else:
        print("Изменений не обнаружено, PATCH-запрос не требуется.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
