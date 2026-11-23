import asyncio, os, queue, re, threading
from apify import Actor
import emailverif as ev

DEFAULT = ["pomexplica@gmail.com", "zz9q8w7e6r5t4y3u2i1o0p@gmail.com", "contact@mailinator.com"]


def clean(xs):
    if isinstance(xs, str):
        xs = [xs]
    out, seen = [], set()
    for x in xs or []:
        if not isinstance(x, str):
            continue
        for p in re.split(r"[\s,;]+", x):
            p = ev.normalize(p)
            if not p:
                continue
            k = p.lower()
            if k in seen:
                continue
            seen.add(k)
            out.append(p)
    return out


async def main():
    async with Actor:
        inp = await Actor.get_input() or {}
        emails = clean(inp.get("emails")) or DEFAULT
        smtp = bool(inp.get("smtpCheck", True))
        catch = bool(inp.get("checkCatchAll", True))
        wait = max(0, min(600, int(inp.get("greylistRetrySeconds", 60) or 0)))
        tout = max(5, min(60, int(inp.get("timeoutSeconds", 12) or 12)))
        proxy = os.environ.get("EMAILVERIF_PROXY") or None
        groups = [g.strip() for g in (os.environ.get("EMAILVERIF_PROXY_GROUPS") or "").split(",") if g.strip()]
        direct = os.environ.get("EMAILVERIF_ALLOW_DIRECT") == "1"
        if direct and ev.forbidden_host():
            direct = False
            Actor.log.warning("Direct port 25 is forbidden on this machine; ignoring EMAILVERIF_ALLOW_DIRECT")
        if smtp and not proxy and not direct:
            # nunca cai para a porta 25 direta da máquina (decisão de Regente m-bd993a2d, 23/11/2026)
            await Actor.fail(status_message="No SMTP exit configured: set EMAILVERIF_PROXY (SOCKS5) or run where "
                             "direct port 25 is allowed, or turn off smtpCheck for a syntax/MX-only check.")
            return
        v = ev.Verifier(proxy=proxy, timeout=tout, check_catch_all=catch, smtp=smtp,
                        log=lambda m: Actor.log.info(m), proxy_groups=groups, allow_direct=direct)
        v.http_proxy = os.environ.get("EMAILVERIF_HTTP_PROXY") or None
        n_disp = await asyncio.get_running_loop().run_in_executor(None, ev.refresh_disposable)
        Actor.log.info(f"{len(emails)} e-mails; HELO {v.helo}; disposable list {len(ev.disposable_set())} domains"
                       f" ({'fresh from GitHub' if n_disp else 'bundled copy'}); proxy {'yes' if proxy else 'no'}")
        q = queue.Queue()
        v.emit = q.put
        st = {"stop": False, "n": 0, "charged": 0, "by": {}}
        done = threading.Event()

        def work():
            try:
                v.verify_all(emails, greylist_wait=wait if smtp else 0, stop=lambda: st["stop"],
                         yahoo=os.environ.get("EMAILVERIF_LOOKUPS", "1") != "0")
            except Exception as e:
                Actor.log.exception(f"verifier crashed: {e}")
            finally:
                done.set()

        th = threading.Thread(target=work, daemon=True)
        th.start()
        while True:
            try:
                it = q.get(timeout=0.3)
            except queue.Empty:
                if done.is_set() and q.empty():
                    break
                await asyncio.sleep(0)
                continue
            it = {k: v for k, v in it.items() if not k.startswith("_")}   # cópia: o verificador ainda usa as marcas
            st["n"] += 1
            st["by"][it["status"]] = st["by"].get(it["status"], 0) + 1
            # cobra só a resposta conclusiva: unknown e erro de sintaxe saem de graça
            pay = it["status"] != "unknown" and it["reason"] != "invalid_syntax"
            if pay and not st["stop"]:
                r = await Actor.push_data(it, charged_event_name="email")
                st["charged"] += 1
                if r is not None and getattr(r, "event_charge_limit_reached", False):
                    st["stop"] = True
                    Actor.log.warning("Maximum cost per run reached; stopping.")
            elif not st["stop"]:
                await Actor.push_data(it)
        ybytes = (v.yahoo.bytes if v.yahoo else 0) + (v.microsoft.bytes if v.microsoft else 0)
        ycalls = (v.yahoo.calls if v.yahoo else 0) + (v.microsoft.calls if v.microsoft else 0)
        Actor.log.info(f"calls={v.smtp_conns + ycalls + v.dns.queries} bytes={v.smtp_bytes + ybytes} "
                       f"smtp_conns={v.smtp_conns} dns={v.dns.queries} yahoo={ycalls}")
        resumo = ", ".join(f"{k} {n}" for k, n in sorted(st["by"].items()))
        await Actor.set_status_message(f"Done: {st['n']} emails ({resumo}); {st['charged']} charged")

asyncio.run(main())
