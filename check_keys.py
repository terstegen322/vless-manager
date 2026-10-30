#!/usr/bin/env python3
"""
check_keys.py — Фоновый скрипт проверки и очистки VLESS-ключей для GitHub Actions.
Архитектура системы:
  1. Читает config.json, db.json и все *.txt файлы из GitHub Gist (GIST_ID, GIST_TOKEN).
  2. Выполняет быстрый TCP-пинг хоста и порта каждого уникального ключа (таймаут 2.5 сек,
     поддержка IPv4, доменов и IPv6 в квадратных скобках).
  3. Обновляет db.json:
     {"<vless_url>": {"first_seen_at", "last_success_at", "silent_days", "hub_added_at" (только в Хабе), ...}}
  4. Фильтрует каждый *.txt файл: если silent_days >= retention_days для этой папки,
     удаляет ключ из файла.
     ИСКЛЮЧЕНИЯ (PROTECTED_FOLDERS): all.txt и favourites.txt никогда не очищаются
     автоматически — они являются постоянным архивом.
     hub.txt (Хаб) — карантинная зона: ключ живёт в Хабе N дней (по умолчанию 7) с момента
     попадания в Хаб (hub_added_at), затем удаляется из Хаба, но остаётся в all.txt.
     В Хабе ключи НЕ удаляются из-за TCP-пинга с GitHub — отбор делает пользователь.
  5. Сохраняет обновленные списки и db.json обратно в Gist одним PATCH-запросом.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

import requests

GITHUB_API_BASE = "https://api.github.com"
TCP_TIMEOUT_SECONDS = 2.5
MAX_WORKERS = 32

# Папки, которые НИКОГДА не очищаются автоматически.
# all.txt — вечный архив всех конфигов.
# favourites.txt — отобранные рабочие конфиги.
PROTECTED_FOLDERS: frozenset[str] = frozenset({"all", "favourites"})

# Дефолтные пороги retention_days для прочих папок.
# hub — карантинная зона: конфиги живут 7 дней и удаляются, если не попали в Любимые.
DEFAULT_RETENTION: dict[str, int] = {"hub": 7}
# Остальные (пользовательские) папки чистятся по «молчанию» ключа — как раньше.
FALLBACK_RETENTION_DAYS = 7
# Имя Хаба (без .txt): единственная папка, где retention_days считается по возрасту ключа в ней.
HUB_STEM = "hub"
EMPTY_FILE_CONTENT = "# empty\n"

# Название подписки в Happ / Incy. Gist не умеет отдавать HTTP-заголовок profile-title, но оба клиента
# читают его и из ПЕРВОЙ строки тела подписки: «#profile-title: Название» (в список серверов эта
# строка не попадает). Максимум 25 символов. Название — обычный UTF-8 текст: Happ допускает plain
# text, а формат «base64:…» для profile-title в его документации не описан (в Happ при проверке
# он отображался как набор букв).
TITLE_PREFIX = "#profile-title"
MAX_TITLE_LEN = 25
DEFAULT_TITLES: dict[str, str] = {"hub": "Хаб", "favourites": "Любимые", "all": "Все"}


def title_directive(title: str) -> str:
    clean = " ".join(title.split())[:MAX_TITLE_LEN] or "VLESS"
    return f"{TITLE_PREFIX}: {clean}"


def with_title_header(content: str, title: str) -> str:
    """Возвращает content с актуальной строкой #profile-title первой (старая строка заменяется)."""
    lines = [ln for ln in content.splitlines() if not ln.strip().lower().startswith(TITLE_PREFIX)]
    body = "\n".join(lines).strip("\n")
    return title_directive(title) + "\n" + (body + "\n" if body else "")


@dataclass(frozen=True)
class VlessEndpoint:
    raw_url: str
    host: str
    port: int
    name: str

    @property
    def target(self) -> tuple[str, int]:
        return (self.host, self.port)


def parse_vless_url(line: str) -> VlessEndpoint | None:
    """
    Парсит vless:// строку, извлекая хост, порт и имя (из #fragment или SNI).
    Поддерживает:
      - vless://uuid@1.2.3.4:443?security=reality#Name
      - vless://uuid@example.com:8443?sni=example.com#Name
      - vless://uuid@[2a01:4f9:c010:82a1::1]:443?security=reality#IPv6
    """
    cleaned = line.strip().strip("'\"`<>")
    if not cleaned.lower().startswith("vless://"):
        return None

    body = cleaned[8:]
    if "#" in body:
        before_hash, raw_frag = body.split("#", 1)
        name = unquote(raw_frag).strip()
    else:
        before_hash, name = body, ""

    if "?" in before_hash:
        authority, query = before_hash.split("?", 1)
    else:
        authority, query = before_hash, ""

    authority = authority.rstrip("/")
    if "@" not in authority:
        return None

    _, hostport = authority.rsplit("@", 1)
    hostport = hostport.strip()
    if not hostport:
        return None

    host = ""
    port = 443

    if hostport.startswith("["):
        close_bracket = hostport.find("]")
        if close_bracket == -1:
            return None
        host = hostport[1:close_bracket].strip().lower()
        rest = hostport[close_bracket + 1 :].strip()
        if rest:
            if not rest.startswith(":"):
                return None
            try:
                port = int(rest[1:])
            except ValueError:
                return None
    else:
        colon_count = hostport.count(":")
        if colon_count == 1:
            raw_h, raw_p = hostport.rsplit(":", 1)
            host = raw_h.strip().lower()
            try:
                port = int(raw_p.strip())
            except ValueError:
                return None
        elif colon_count == 0:
            host = hostport.lower()
            port = 443
        else:
            host = hostport.strip("[]").lower()
            port = 443

    if not host or not (1 <= port <= 65535):
        return None

    if not name:
        sni = ""
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                if k.lower() == "sni" and v:
                    sni = unquote(v).strip()
                    break
        name = sni or f"{host}:{port}"

    return VlessEndpoint(
        raw_url=cleaned,
        host=host,
        port=port,
        name=name,
    )


def tcp_ping(host: str, port: int, timeout: float = TCP_TIMEOUT_SECONDS) -> tuple[bool, float | None]:
    """
    Быстрый TCP/Handshake пинг с поддержкой IPv4, DNS и IPv6.
    """
    clean_host = host.strip("[]")
    if not clean_host:
        return False, None

    try:
        addr_infos = socket.getaddrinfo(
            clean_host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        return False, None

    for family, socktype, proto, _, sockaddr in addr_infos:
        s: socket.socket | None = None
        start = time.perf_counter()
        try:
            s = socket.socket(family, socktype, proto)
            s.settimeout(timeout)
            s.connect(sockaddr)
            latency_ms = round((time.perf_counter() - start) * 1000.0, 1)
            return True, latency_ms
        except (socket.timeout, ConnectionError, OSError):
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    return False, None


def parse_iso(val: str | None, default: datetime) -> datetime:
    if not val or not isinstance(val, str):
        return default
    s = val.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return default


def main() -> int:
    gist_token = (os.environ.get("GIST_TOKEN") or os.environ.get("GIST_PAT") or "").strip()
    gist_id = (os.environ.get("GIST_ID") or os.environ.get("MY_GIST_ID") or "").strip()

    if not gist_token or not gist_id:
        print("Ошибка: задайте переменные окружения GIST_TOKEN и GIST_ID.", file=sys.stderr)
        return 1

    headers = {
        "Authorization": f"Bearer {gist_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vless-vault-checker/1.0",
    }

    print(f"-> Чтение Gist {gist_id}...")
    resp = requests.get(f"{GITHUB_API_BASE}/gists/{gist_id}", headers=headers, timeout=20)
    if resp.status_code != 200:
        print(f"Ошибка HTTP {resp.status_code}: {resp.text[:250]}", file=sys.stderr)
        return 1

    gist_data = resp.json()
    files_dict = gist_data.get("files") or {}

    file_contents: dict[str, str] = {}
    for fname, meta in files_dict.items():
        if not isinstance(meta, dict):
            continue
        if meta.get("truncated") and meta.get("raw_url"):
            raw_r = requests.get(meta["raw_url"], headers=headers, timeout=20)
            raw_r.raise_for_status()
            file_contents[fname] = raw_r.text
        else:
            file_contents[fname] = meta.get("content") or ""

    # 1. Читаем config.json (retention_days, titles)
    retention_days: dict[str, int] = {}
    titles: dict[str, str] = {}
    if "config.json" in file_contents:
        try:
            cfg = json.loads(file_contents["config.json"])
            raw_titles = cfg.get("titles") if isinstance(cfg, dict) else None
            if isinstance(raw_titles, dict):
                for tk, tv in raw_titles.items():
                    if isinstance(tv, str) and tv.strip():
                        titles[tk[:-4] if tk.endswith(".txt") else tk] = tv.strip()
            source = cfg.get("retention_days") or cfg.get("folders") or cfg
            if isinstance(source, dict):
                for k, v in source.items():
                    val = v if isinstance(v, (int, float)) else (v.get("max_silent_days") if isinstance(v, dict) else None)
                    if val is not None:
                        clean_k = k[:-4] if k.endswith(".txt") else k
                        retention_days[clean_k] = int(val)
        except Exception as e:
            print(f"Предупреждение при разборе config.json: {e}")

    # 2. Читаем db.json
    db_json: dict[str, Any] = {}
    if "db.json" in file_contents:
        try:
            db_json = json.loads(file_contents["db.json"])
            if not isinstance(db_json, dict):
                db_json = {}
        except Exception:
            db_json = {}

    # 3. Собираем все *.txt файлы
    txt_files = sorted([f for f in file_contents.keys() if f.lower().endswith(".txt")])
    if not txt_files:
        print("В Gist не найдено ни одного *.txt файла.")
        return 0

    parsed_per_file: dict[str, list[VlessEndpoint]] = {}
    unique_endpoints: set[tuple[str, int]] = set()

    for fn in txt_files:
        content = file_contents[fn]
        endpoints: list[VlessEndpoint] = []
        seen_in_file: set[str] = set()
        for line in content.splitlines():
            ep = parse_vless_url(line)
            if ep is None:
                continue
            if ep.raw_url in seen_in_file:
                continue
            seen_in_file.add(ep.raw_url)
            endpoints.append(ep)
            unique_endpoints.add(ep.target)
        parsed_per_file[fn] = endpoints

    print(f"-> Папок: {len(txt_files)}, уникальных серверов (host:port): {len(unique_endpoints)}.")

    # 4. Проверяем TCP-доступность
    ping_results: dict[tuple[str, int], tuple[bool, float | None]] = {}
    if unique_endpoints:
        workers = min(MAX_WORKERS, len(unique_endpoints))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            future_to_ep = {
                ex.submit(tcp_ping, host, port, TCP_TIMEOUT_SECONDS): (host, port)
                for host, port in unique_endpoints
            }
            for fut in as_completed(future_to_ep):
                ep = future_to_ep[fut]
                try:
                    ping_results[ep] = fut.result()
                except Exception:
                    ping_results[ep] = (False, None)

    alive_count = sum(1 for ok, _ in ping_results.values() if ok)
    print(f"-> Доступно серверов: {alive_count}/{len(unique_endpoints)}.")

    now = datetime.now(timezone.utc)
    now_iso = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # 5. Обновляем db.json для всех найденных vless_url
    all_seen_urls: set[str] = set()
    new_db: dict[str, Any] = {}

    hub_urls: set[str] = {ep.raw_url for ep in parsed_per_file.get(f"{HUB_STEM}.txt", [])}

    for fn, endpoints in parsed_per_file.items():
        for ep in endpoints:
            url = ep.raw_url
            all_seen_urls.add(url)
            if url in new_db:
                continue

            prev = db_json.get(url) if isinstance(db_json.get(url), dict) else {}
            prev_success = prev.get("last_success_at")
            # Когда ключ впервые увидели: нужен, чтобы ключи, которые НИ РАЗУ не ответили,
            # тоже начинали копить «молчание» и в итоге удалялись.
            first_seen = prev.get("first_seen_at") or now_iso
            is_alive, latency = ping_results.get(ep.target, (False, None))

            if is_alive:
                last_success = now_iso
                silent_days = 0
            else:
                last_success = prev_success
                ref = parse_iso(prev_success or first_seen, now)
                diff = max(0.0, (now - ref).total_seconds() / 86400.0)
                silent_days = int(diff)

            new_db[url] = {
                "first_seen_at": first_seen,
                "last_success_at": last_success,
                "silent_days": silent_days,
                "alive": is_alive,
                "latency_ms": latency,
                "last_checked_at": now_iso,
            }
            if url in hub_urls:
                # Момент попадания ИМЕННО В ХАБ (а не первого появления ключа где-либо):
                # ключ, давно лежащий в «Все» и перенесённый в Хаб, получает полный срок.
                # У ключей, попавших в Хаб до появления этого поля, срок стартует с этого запуска.
                new_db[url]["hub_added_at"] = prev.get("hub_added_at") or now_iso

    # 6. Фильтруем *.txt файлы:
    #    - PROTECTED_FOLDERS (all, favourites) пропускаются — вечный архив;
    #    - hub.txt — по ВОЗРАСТУ ключа в Хабе (hub_added_at >= retention);
    #    - остальные папки — по «молчанию» (silent_days >= retention).
    patch_payload: dict[str, Any] = {}
    total_removed = 0
    hub_kept_urls: set[str] = set()

    for fn in txt_files:
        stem = fn[:-4]

        folder_title = titles.get(stem) or DEFAULT_TITLES.get(stem) or stem

        # Защищённые папки — никогда не чистим автоматически (только проставляем название подписки)
        if stem in PROTECTED_FOLDERS:
            print(f"  [✓] Папка {fn} защищена (вечный архив) — пропускаем очистку.")
            titled = with_title_header(file_contents.get(fn, ""), folder_title)
            if file_contents.get(fn) != titled:
                patch_payload[fn] = {"content": titled}
            continue

        retention = retention_days.get(
            stem,
            DEFAULT_RETENTION.get(stem, FALLBACK_RETENTION_DAYS),
        )

        kept: list[str] = []
        removed_in_folder = 0

        is_hub = stem == HUB_STEM

        for ep in parsed_per_file[fn]:
            meta = new_db.get(ep.raw_url, {})

            if is_hub:
                # Хаб: считаем дни с момента попадания в Хаб. Из-за TCP-пинга с GitHub ключ
                # не удаляется — отбор рабочих делает пользователь своим пингом в клиенте.
                added = parse_iso(meta.get("hub_added_at"), now)
                age_days = max(0.0, (now - added).total_seconds() / 86400.0)
                if age_days >= retention:
                    removed_in_folder += 1
                    total_removed += 1
                    print(
                        f"  [-] Убран из Хаба: {ep.name} ({ep.host}:{ep.port})"
                        f" — в Хабе {age_days:.1f} дн. >= {retention} дн."
                    )
                else:
                    kept.append(ep.raw_url)
                    hub_kept_urls.add(ep.raw_url)
                continue

            s_days = meta.get("silent_days", 0)
            if s_days >= retention:
                removed_in_folder += 1
                total_removed += 1
                print(
                    f"  [-] Удален из {fn}: {ep.name} ({ep.host}:{ep.port})"
                    f" — молчит {s_days} дн. >= {retention} дн."
                )
            else:
                kept.append(ep.raw_url)

        new_content = "\n".join(kept) + "\n" if kept else EMPTY_FILE_CONTENT
        new_content = with_title_header(new_content, folder_title)
        if file_contents.get(fn) != new_content:
            patch_payload[fn] = {"content": new_content}

        basis = "в Хабе" if is_hub else "молчания"
        print(f"  [i] Папка {fn} (порог {retention} дн. по {basis}): осталось {len(kept)}, удалено {removed_in_folder}.")

    # Очищаем db.json от ключей, которых больше нет ни в одной папке
    surviving_urls = set()
    for fn in txt_files:
        content = patch_payload[fn]["content"] if fn in patch_payload else file_contents.get(fn, "")
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("vless://"):
                surviving_urls.add(line)

    pruned_db = {url: meta for url, meta in new_db.items() if url in surviving_urls}
    # Ключ покинул Хаб (срок вышел или перенесён в «Любимые») — забываем время входа:
    # при возвращении в Хаб срок пойдёт заново.
    for url, meta in pruned_db.items():
        if url not in hub_kept_urls:
            meta.pop("hub_added_at", None)
    new_db_str = json.dumps(pruned_db, ensure_ascii=False, indent=2) + "\n"

    if file_contents.get("db.json") != new_db_str:
        patch_payload["db.json"] = {"content": new_db_str}

    if "config.json" not in file_contents:
        # В config.json записываем только НЕзащищённые папки (у них есть настраиваемый retention).
        default_cfg = {
            "protected_folders": sorted(PROTECTED_FOLDERS),
            "retention_days": {
                fn[:-4]: retention_days.get(fn[:-4], DEFAULT_RETENTION.get(fn[:-4], FALLBACK_RETENTION_DAYS))
                for fn in txt_files
                if fn[:-4] not in PROTECTED_FOLDERS
            },
            "titles": {fn[:-4]: DEFAULT_TITLES.get(fn[:-4], fn[:-4]) for fn in txt_files},
        }
        patch_payload["config.json"] = {"content": json.dumps(default_cfg, indent=2) + "\n"}

    if not patch_payload:
        print("-> Нет изменений для отправки в Gist.")
        return 0

    print(f"-> Отправка изменений в Gist {gist_id} (удалено устаревших ключей: {total_removed})...")
    patch_res = requests.patch(
        f"{GITHUB_API_BASE}/gists/{gist_id}",
        headers=headers,
        json={"files": patch_payload},
        timeout=25,
    )
    if patch_res.status_code != 200:
        print(f"Ошибка сохранения в Gist: HTTP {patch_res.status_code} — {patch_res.text[:250]}", file=sys.stderr)
        return 1

    print("-> Успешно! Списки ключей и db.json обновлены.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
