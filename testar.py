"""Roda o src/main.py na VPS, sem a Apify, do mesmo jeito que o pom-robos (SDK local, armazenamento temporário).

Uso: python3 testar.py <caso> [<caso>...]   (sem caso: todos)
Grava teste_<caso>.json com os itens e a medida (segundos, bytes da rede, chamadas, itens por status).
Os casos vêm de casos.json (endereços públicos conhecidos e inventados).
"""
import collections, json, os, re, shutil, subprocess, sys, tempfile, time

AQUI = os.path.dirname(os.path.abspath(__file__))
PY = os.environ.get("TESTAR_PY") or "/opt/money-video/ferramentas/pom-robos/.venv/bin/python"
CASOS = {"padrao": {}}
if os.path.exists(os.path.join(AQUI, "casos.json")):
    CASOS.update(json.load(open(os.path.join(AQUI, "casos.json"))))


def rodar(nome, entrada):
    tmp = tempfile.mkdtemp(prefix="emailverif-")
    try:
        os.makedirs(os.path.join(tmp, "key_value_stores/default"))
        json.dump(entrada, open(os.path.join(tmp, "key_value_stores/default/INPUT.json"), "w"))
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": tmp, "LANG": "C.UTF-8", "APIFY_LOCAL_STORAGE_DIR": tmp,
               "PYTHONPATH": os.path.join(AQUI, "src"), "PYTHONDONTWRITEBYTECODE": "1",
               "EMAILVERIF_HELO": os.environ.get("EMAILVERIF_HELO") or "srv2118426.hstgr.cloud"}
        for k in ("EMAILVERIF_PROXY", "EMAILVERIF_HTTP_PROXY", "EMAILVERIF_MAX_CONN_PER_MIN", "EMAILVERIF_PREFER_IPV6", "EMAILVERIF_PROXY_GROUPS", "EMAILVERIF_ALLOW_DIRECT", "EMAILVERIF_FROM"):
            if os.environ.get(k):
                env[k] = os.environ[k]
        t0 = time.time()
        p = subprocess.run([PY, os.path.join(AQUI, "src/main.py")], cwd=tmp, env=env, capture_output=True, text=True, timeout=1800)
        seg = round(time.time() - t0, 1)
        log = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr)
        rede = re.findall(r"calls=(\d+) bytes=(\d+) smtp_conns=(\d+) dns=(\d+) yahoo=(\d+)", log)
        msg = re.findall(r"\[Status message\]: (.*)", log)
        ds = os.path.join(tmp, "datasets/default")
        itens = [json.load(open(os.path.join(ds, n))) for n in sorted((n for n in os.listdir(ds) if re.fullmatch(r"\d+\.json", n)), key=lambda n: int(n[:-5]))] if os.path.isdir(ds) else []
        med = {"caso": nome, "exit": p.returncode, "segundos": seg,
               "chamadas": int(rede[-1][0]) if rede else None, "bytes_rede": int(rede[-1][1]) if rede else None,
               "conexoes_smtp": int(rede[-1][2]) if rede else None, "dns": int(rede[-1][3]) if rede else None,
               "yahoo": int(rede[-1][4]) if rede else None,
               "entrada": len(entrada.get("emails") or []) or None, "itens": len(itens),
               "bytes_saida": len(json.dumps(itens, ensure_ascii=False).encode()),
               "por_status": dict(collections.Counter(i.get("status") for i in itens)),
               "por_motivo": dict(collections.Counter(i.get("reason") for i in itens)),
               "provedores": dict(collections.Counter(i.get("provider") for i in itens)),
               "ms_medio": int(sum(i.get("checkMs") or 0 for i in itens) / max(1, len(itens))),
               "status": msg[-1] if msg else None}
        print(json.dumps(med, ensure_ascii=False))
        if p.returncode:
            print(log[-2500:])
        json.dump({"medida": med, "entrada": entrada, "itens": itens}, open(os.path.join(AQUI, f"teste_{nome}.json"), "w"), ensure_ascii=False, indent=1)
        return med
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    for k in sys.argv[1:] or CASOS:
        rodar(k, CASOS[k])
