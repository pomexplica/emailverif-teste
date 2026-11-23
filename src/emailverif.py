"""Verificador de e-mail: sintaxe, MX, conversa SMTP até o RCPT TO (nunca DATA), domínio que aceita tudo,
descartável e de função.

Regras de respeito aos provedores (Drucker, 23/11/2026):
- uma conexão por vez por grupo de MX (gmail.com e os domínios do Google Workspace contam como o mesmo grupo);
- pausa entre conexões ao mesmo grupo e uma pausa curta entre RCPTs;
- no máximo RCPT_POR_CONEXAO destinatários por conexão;
- cache de MX por domínio;
- resposta 4xx (greylisting, limite) vira 'unknown' e ganha uma nova tentativa no fim, depois de uma espera.
A conversa termina em RSET/QUIT depois dos RCPT TO; o robô nunca manda DATA, então nenhum e-mail é enviado.
"""
import os, random, re, socket, ssl, string, threading, time
from concurrent.futures import ThreadPoolExecutor

import dns.exception, dns.resolver

AQUI = os.path.dirname(os.path.abspath(__file__))
RCPT_POR_CONEXAO = 20
PAUSA_CONEXAO = 1.0
PAUSA_RCPT = 0.15
# teto global de conexões SMTP novas por minuto (todas as conexões, todos os grupos). Em 23/11/2026 a porta 25
# por IPv4 da VPS parou de sair depois de ~20 conexões em 8 min (docs/incidentes.md, 18:42).
MAX_CONN_MIN = float(os.environ.get("EMAILVERIF_MAX_CONN_PER_MIN", "12"))
_conn_lock = threading.Lock()
_conn_last = [0.0]


def _conn_slot():
    if MAX_CONN_MIN <= 0:
        return
    with _conn_lock:
        espera = 60.0 / MAX_CONN_MIN - (time.time() - _conn_last[0])
        if espera > 0:
            time.sleep(espera)
        _conn_last[0] = time.time()

# --- listas -------------------------------------------------------------------------------------------------

ROLE = set("""
abuse accounting accounts admin administracao administrador administrator adm atendimento billing biz boss
careers carreiras cobranca comercial compras compliance contact contacts contato contatos contabilidade
contactus contato.site customer customercare customerservice customersupport cv dev developers devnull
diretoria editor editorial enquiries enquiry equipe events eventos faleconosco finance financeiro fiscal
hello help helpdesk hi hostmaster hr imprensa info informacoes information investor investors ir it jobs
juridico legal license list mail mailer-daemon mailerdaemon management marketing media news newsletter
no-reply noc noreply null office ola online operations orders ouvidoria partners parcerias payments
pedidos postmaster pr press privacy produto recepcao recrutamento recruiting recruitment reservas
reservations rh root sac sales secretaria security service services shop social suporte support team
tech billing usenet uucp vendas webmaster welcome www
""".split())

FREE = set("""
gmail.com googlemail.com hotmail.com hotmail.com.br hotmail.co.uk hotmail.fr hotmail.es hotmail.it outlook.com
outlook.com.br outlook.pt live.com live.com.br msn.com yahoo.com yahoo.com.br yahoo.co.uk yahoo.fr yahoo.es
yahoo.it yahoo.de yahoo.co.jp yahoo.com.ar yahoo.com.mx ymail.com rocketmail.com aol.com icloud.com me.com
mac.com bol.com.br uol.com.br terra.com.br ig.com.br globo.com globomail.com r7.com zipmail.com.br
protonmail.com proton.me pm.me gmx.com gmx.de gmx.net mail.com zoho.com zohomail.com yandex.com yandex.ru
mail.ru qq.com 163.com 126.com web.de t-online.de libero.it orange.fr free.fr laposte.net tutanota.com
tuta.io hey.com fastmail.com
""".split())

POPULARES = ["gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.com.br", "hotmail.com.br",
             "outlook.com.br", "live.com", "icloud.com", "aol.com", "bol.com.br", "uol.com.br", "terra.com.br",
             "ig.com.br", "msn.com", "protonmail.com", "mail.com", "gmx.com", "yandex.com", "zoho.com", "me.com",
             "globo.com", "googlemail.com", "ymail.com"]

# provedor pelo nome do servidor de MX (fim do nome -> rótulo)
PROVEDORES = [
    ("gmail-smtp-in.l.google.com", "Google"), ("google.com", "Google"), ("googlemail.com", "Google"),
    ("smtp.google.com", "Google"),
    ("olc.protection.outlook.com", "Microsoft (Outlook.com/Hotmail)"),
    ("mail.protection.outlook.com", "Microsoft 365"), ("outlook.com", "Microsoft"), ("hotmail.com", "Microsoft"),
    ("yahoodns.net", "Yahoo"), ("aol.com", "Yahoo (AOL)"),
    ("icloud.com", "Apple iCloud"), ("me.com", "Apple iCloud"),
    ("zoho.com", "Zoho"), ("zoho.eu", "Zoho"), ("zohomail.com", "Zoho"),
    ("protonmail.ch", "Proton"), ("proton.me", "Proton"),
    ("pphosted.com", "Proofpoint"), ("ppe-hosted.com", "Proofpoint"), ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"), ("iphmx.com", "Cisco Secure Email"), ("messagelabs.com", "Broadcom"),
    ("trendmicro.com", "Trend Micro"), ("sophos.com", "Sophos"), ("fortimail.com", "Fortinet"),
    ("mailgun.org", "Mailgun"), ("sendgrid.net", "SendGrid"), ("amazonaws.com", "Amazon SES"),
    ("yandex.net", "Yandex"), ("yandex.ru", "Yandex"), ("mail.ru", "Mail.ru"), ("gmx.net", "GMX"),
    ("web.de", "Web.de"), ("qq.com", "Tencent QQ"), ("163.com", "NetEase"), ("fastmail.com", "Fastmail"),
    ("messagingengine.com", "Fastmail"), ("titan.email", "Titan"), ("hostinger.com", "Hostinger"),
    ("locaweb.com.br", "Locaweb"), ("uol.com.br", "UOL"), ("terra.com.br", "Terra"), ("kinghost.net", "KingHost"),
    ("hostgator.com.br", "HostGator"), ("secureserver.net", "GoDaddy"), ("ovh.net", "OVH"),
    ("emailsrvr.com", "Rackspace"), ("mailchannels.net", "MailChannels"), ("improvmx.com", "ImprovMX"),
    ("forwardemail.net", "Forward Email"), ("cloudflare.net", "Cloudflare Email Routing"),
    ("mx.cloudflare.net", "Cloudflare Email Routing"), ("tutanota.de", "Tuta"), ("hey.com", "HEY"),
]

_disp = None
_disp_lock = threading.Lock()


def disposable_set():
    global _disp
    with _disp_lock:
        if _disp is None:
            s = set()
            for nome in ("disposable_domains.txt",):
                p = os.path.join(AQUI, nome)
                if os.path.exists(p):
                    s.update(l.strip().lower() for l in open(p, encoding="utf-8") if l.strip() and not l.startswith("#"))
            _disp = s
        return _disp


def refresh_disposable(timeout=6):
    """Baixa a lista do GitHub (disposable-email-domains). Se falhar, fica a cópia que vai com o robô."""
    import urllib.request
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
    try:
        txt = urllib.request.urlopen(url, timeout=timeout).read().decode()
        novos = {l.strip().lower() for l in txt.splitlines() if l.strip() and not l.startswith("#")}
        if len(novos) > 1000:
            disposable_set().update(novos)
            return len(novos)
    except Exception:
        pass
    return 0


def is_disposable(domain):
    ds = disposable_set()
    parts = domain.split(".")
    return any(".".join(parts[i:]) in ds for i in range(len(parts) - 1))


def provider_of(mx_host, domain):
    h = (mx_host or "").lower().rstrip(".")
    for fim, nome in PROVEDORES:
        if h == fim or h.endswith("." + fim):
            if nome == "Google":
                return "Gmail" if domain in ("gmail.com", "googlemail.com") else "Google Workspace"
            return nome
    if not h:
        return None
    partes = h.split(".")
    return ".".join(partes[-3:] if len(partes[-1]) == 2 and len(partes) > 2 and partes[-2] in ("com", "net", "org", "co") else partes[-2:])


def mx_group(mx_host):
    """Chave do grupo de servidores (uma conexão por vez por grupo)."""
    h = (mx_host or "").lower().rstrip(".")
    for fim in ("google.com", "googlemail.com", "outlook.com", "yahoodns.net", "pphosted.com", "mimecast.com",
                "iphmx.com", "zoho.com", "icloud.com"):
        if h.endswith(fim):
            return fim
    return h


def _lev(a, b):
    """Distância de edição com troca de vizinhas valendo 1 (gmial -> gmail = 1)."""
    if abs(len(a) - len(b)) > 2:
        return 9
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def did_you_mean(local, domain):
    if domain in POPULARES or domain in FREE:
        return None
    for d in POPULARES:
        if _lev(domain, d) <= 1:
            return f"{local}@{d}"
    for errado, certo in ((".con", ".com"), (".cmo", ".com"), (".comm", ".com"), (".om", ".com"), (".co.br", ".com.br")):
        if domain.endswith(errado) and domain[: -len(errado)] + certo in POPULARES:
            return f"{local}@{domain[:-len(errado)]}{certo}"
    return None


# --- sintaxe ------------------------------------------------------------------------------------------------

LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize(raw):
    e = raw.strip().strip("<>").strip()
    if e.lower().startswith("mailto:"):
        e = e[7:].split("?")[0]
    return e.strip().strip(".,;")


def syntax(email):
    """(ok, local, domain_ascii, motivo)"""
    if email.count("@") != 1:
        return False, None, None, "The address must have exactly one @"
    local, dom = email.rsplit("@", 1)
    if not local or not dom:
        return False, local or None, dom.lower() or None, "Empty local part or domain"
    if len(local) > 64:
        return False, local, dom.lower(), "Local part longer than 64 characters"
    if not LOCAL_RE.match(local):
        return False, local, dom.lower(), "Local part has characters that are not allowed or misplaced dots"
    try:
        da = dom.rstrip(".").encode("idna").decode("ascii").lower()
    except Exception:
        return False, local, dom.lower(), "Domain is not a valid name"
    labels = da.split(".")
    if len(da) > 253 or len(labels) < 2 or not all(LABEL_RE.match(l) for l in labels):
        return False, local, da, "Domain is not a valid name"
    if not (re.fullmatch(r"[a-z]{2,63}", labels[-1]) or labels[-1].startswith("xn--")):
        return False, local, da, "Top-level domain is not valid"
    if len(local) + 1 + len(da) > 254:
        return False, local, da, "Address longer than 254 characters"
    return True, local, da, None


# --- DNS ----------------------------------------------------------------------------------------------------

class DNS:
    def __init__(self, timeout=8.0):
        self.r = dns.resolver.Resolver()
        self.r.lifetime = timeout
        self.r.timeout = min(4.0, timeout)
        self.cache = {}
        self.lock = threading.Lock()
        self.queries = 0

    def mx(self, domain):
        """-> ('ok', [hosts]) | ('nxdomain'|'no_mx'|'null_mx'|'dns_error', motivo)"""
        with self.lock:
            if domain in self.cache:
                return self.cache[domain]
        res = self._mx(domain)
        with self.lock:
            self.cache[domain] = res
        return res

    def _mx(self, domain):
        for tentativa in range(2):
            try:
                self.queries += 1
                ans = self.r.resolve(domain, "MX")
                recs = sorted(((r.preference, str(r.exchange).rstrip(".").lower()) for r in ans), key=lambda x: x[0])
                if len(recs) == 1 and recs[0][1] in ("", "."):
                    return ("null_mx", "The domain publishes a null MX: it does not accept email")
                hosts = [h for _, h in recs if h and h != "."]
                if hosts:
                    return ("ok", hosts)
                return ("no_mx", "No mail server (MX) for the domain")
            except dns.resolver.NXDOMAIN:
                return ("nxdomain", "The domain does not exist (NXDOMAIN)")
            except dns.resolver.NoAnswer:
                # RFC 5321 5.1: sem MX, o próprio domínio (A/AAAA) recebe
                try:
                    self.queries += 1
                    self.r.resolve(domain, "A")
                    return ("ok", [domain])
                except Exception:
                    return ("no_mx", "No MX and no A record: the domain cannot receive email")
            except dns.resolver.NoNameservers as e:
                err = f"DNS servers failed for the domain ({str(e)[:80]})"
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
                err = "DNS lookup timed out"
            except Exception as e:
                err = f"DNS error: {type(e).__name__}"
            time.sleep(0.5)
        return ("dns_error", err)


# --- SMTP ---------------------------------------------------------------------------------------------------

class SMTPError(Exception):
    pass


def _socks5_connect(proxy, host, port, timeout):
    """proxy = socks5h://[user:pass@]host:port (o nome do MX é resolvido pelo proxy)."""
    m = re.match(r"socks5h?://(?:([^:@/]*):([^@/]*)@)?([^:/]+):(\d+)", proxy)
    if not m:
        raise SMTPError(f"Bad proxy URL")
    user, pw, ph, pp = m.group(1), m.group(2), m.group(3), int(m.group(4))
    s = socket.create_connection((ph, pp), timeout=timeout)
    s.settimeout(timeout)
    if user:
        s.sendall(b"\x05\x01\x02")
    else:
        s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if len(r) < 2 or r[0] != 5:
        raise SMTPError("SOCKS5 proxy did not answer")
    if r[1] == 2:
        u, p = (user or "").encode(), (pw or "").encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        a = s.recv(2)
        if len(a) < 2 or a[1] != 0:
            raise SMTPError("SOCKS5 proxy refused the credentials")
    elif r[1] != 0:
        raise SMTPError("SOCKS5 proxy asks for an unsupported auth method")
    hb = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big"))
    r = s.recv(4)
    if len(r) < 4 or r[1] != 0:
        codes = {1: "general failure", 2: "not allowed", 3: "network unreachable", 4: "host unreachable",
                 5: "connection refused", 6: "TTL expired"}
        raise SMTPError(f"SOCKS5 connect failed: {codes.get(r[1] if len(r) > 1 else 1, 'error')}")
    atyp = r[3]
    s.recv({1: 4, 4: 16}.get(atyp, 0) + 2 if atyp != 3 else s.recv(1)[0] + 2)
    return s


V4_DEAD = threading.Event()   # a porta 25 por IPv4 deu tempo esgotado nesta rodada
if os.environ.get("EMAILVERIF_PREFER_IPV6") == "1":
    V4_DEAD.set()


class Conversa:
    """Uma conexão SMTP: banner, EHLO, STARTTLS (se houver), MAIL FROM, vários RCPT TO, QUIT. Nunca DATA."""

    def __init__(self, host, helo, mail_from, timeout, proxy=None, ipv6=False, starttls=True):
        self.host, self.helo, self.mail_from, self.timeout = host, helo, mail_from, timeout
        self.proxy, self.ipv6, self.use_tls = proxy, ipv6, starttls
        self.sock = self.f = None
        self.bytes = 0
        self.tls = False
        self.family = None
        self.tx_rcpts = 0

    def _conn(self):
        if self.proxy:
            return _socks5_connect(self.proxy, self.host, 25, self.timeout)
        v4 = [a for a in socket.getaddrinfo(self.host, 25, socket.AF_INET, socket.SOCK_STREAM)][:2] if True else []
        try:
            v6 = [a for a in socket.getaddrinfo(self.host, 25, socket.AF_INET6, socket.SOCK_STREAM)][:2] if self.ipv6 else []
        except socket.gaierror:
            v6 = []
        # IPv4 primeiro; se o IPv4 da porta 25 já caiu nesta rodada (V4_DEAD), IPv6 primeiro
        order = (v6 + v4) if V4_DEAD.is_set() else (v4 + v6)
        if V4_DEAD.is_set() and not v6:
            order = v4[:1]   # IPv4 já caiu e não há IPv6: uma tentativa curta só
        last = None
        for af, st, proto, _, sa in order:
            try:
                s = socket.socket(af, st, proto)
                s.settimeout(5.0 if (V4_DEAD.is_set() and af == socket.AF_INET) else min(8.0, self.timeout))
                s.connect(sa)
                self.family = "ipv6" if af == socket.AF_INET6 else "ipv4"
                return s
            except OSError as e:
                last = e
                if af == socket.AF_INET and isinstance(e, (socket.timeout, TimeoutError)) and v6:
                    V4_DEAD.set()
                try:
                    s.close()
                except Exception:
                    pass
        raise last or SMTPError("no address for MX")

    def _read(self):
        lines = []
        while True:
            l = self.f.readline()
            if not l:
                raise SMTPError("connection closed by server")
            self.bytes += len(l)
            l = l.decode("utf-8", "replace").rstrip("\r\n")
            lines.append(l)
            if len(l) < 4 or l[3] != "-":
                break
            if len(lines) > 100:
                break
        code = int(lines[-1][:3]) if lines[-1][:3].isdigit() else 0
        text = " ".join(x[4:].strip() for x in lines)
        return code, text

    def cmd(self, c):
        data = (c + "\r\n").encode()
        self.bytes += len(data)
        self.sock.sendall(data)
        return self._read()

    def open(self):
        self.sock = self._conn()
        self.sock.settimeout(self.timeout)
        self.f = self.sock.makefile("rb")
        code, text = self._read()
        if code != 220:
            raise SMTPError(f"banner {code} {text[:120]}", code, text)
        code, text = self.cmd(f"EHLO {self.helo}")
        ehlo_ok = code == 250
        if not ehlo_ok:
            code, text = self.cmd(f"HELO {self.helo}")
            if code != 250:
                raise SMTPError(f"HELO {code} {text[:120]}", code, text)
        if ehlo_ok and self.use_tls and "STARTTLS" in text.upper():
            c2, t2 = self.cmd("STARTTLS")
            if c2 == 220:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)
                self.f = self.sock.makefile("rb")
                self.tls = True
                code, text = self.cmd(f"EHLO {self.helo}")
                if code != 250:
                    raise SMTPError(f"EHLO after STARTTLS {code} {text[:120]}", code, text)
        code, text = self.cmd(f"MAIL FROM:<{self.mail_from}>")
        if code != 250:
            raise SMTPError(f"MAIL FROM {code} {text[:160]}", code, text)

    def new_tx(self):
        c, t = self.cmd("RSET")
        c, t = self.cmd(f"MAIL FROM:<{self.mail_from}>")
        if c != 250:
            raise SMTPError(f"MAIL FROM {c} {t[:160]}", c, t)
        self.tx_rcpts = 0

    def rcpt(self, addr, one_per_tx=False):
        """RCPT TO. one_per_tx: um destinatário por transação (Outlook.com/Hotmail: sem isso, o 2º RCPT de
        outra região volta 452 4.5.3 e, em um teste, um endereço inventado voltou 250)."""
        if one_per_tx and self.tx_rcpts:
            self.new_tx()
        c, t = self.cmd(f"RCPT TO:<{addr}>")
        self.tx_rcpts += 1
        if c == 452 and re.search(r"multiple regions|4\.5\.3", t or "", re.I):
            self.new_tx()
            c, t = self.cmd(f"RCPT TO:<{addr}>")
            self.tx_rcpts += 1
        return c, t

    def close(self):
        try:
            if self.sock:
                try:
                    self.cmd("QUIT")
                except Exception:
                    pass
                self.sock.close()
        except Exception:
            pass


TEMP_REASONS = ("greylisted", "temporary_error", "too_many_recipients", "smtp_timeout", "proxy_error")
ENH_RE = re.compile(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b")
USER_RE = re.compile(r"(does not exist|doesn'?t exist|no such (user|mailbox|recipient|address)|user unknown|unknown user|"
                     r"unknown recipient|recipient (address )?rejected|address rejected|invalid (recipient|mailbox|address)|"
                     r"mailbox (unavailable|not found|does not exist|disabled|is disabled|inactive)|not a valid mailbox|"
                     r"user not found|recipient not found|account (has been )?(disabled|deactivated|suspended)|"
                     r"no mailbox|undeliverable address|address unknown|unrouteable address|not our customer|"
                     r"doesn't have a .* account|nao existe|inexistente|usuario desconhecido)", re.I)
SENDER_RE = re.compile(r"(sender address rejected|sender verify|domain of sender|sender domain|reverse dns|reverse hostname|"
                       r"ip name lookup|no reverse|ptr record|helo command rejected|client host rejected|"
                       r"connection rejected)", re.I)
BLOCK_RE = re.compile(r"(spamhaus|blocked|blacklist|block ?list|dnsbl|\brbl\b|reputation|banned|policy|"
                      r"not allowed to send|client host|sender ip|your ip|access denied|too many|rate limit|"
                      r"temporarily (deferred|rejected)|authentication required|relay|ptr|reverse dns|helo)", re.I)


def classify(code, text):
    """Resposta ao RCPT TO -> ('accepted'|'rejected'|'blocked'|'temp'|'ambiguous', motivo)"""
    enh = ENH_RE.search(text or "")
    enh_s = enh.group(0) if enh else None
    if code in (250, 251):
        return "accepted", "mailbox_exists"
    if code == 252:
        return "ambiguous", "server_cannot_verify"
    if 400 <= code < 500:
        if re.search(r"grey|gray|try again later|greylist", text or "", re.I):
            return "temp", "greylisted"
        if code == 452 or re.search(r"too many", text or "", re.I):
            return "temp", "too_many_recipients"
        return "temp", "temporary_error"
    if 500 <= code < 600:
        t = text or ""
        # problema com o remetente ou com o IP de saída (não com a caixa): 5.1.7, 5.1.8, rDNS, "sender verify"
        if (enh_s in ("5.1.7", "5.1.8") or SENDER_RE.search(t)):
            return "blocked", "smtp_blocked"
        # Microsoft 365 (DBEB): "550 5.4.1 Recipient address rejected: Access denied" = caixa não existe
        if enh_s and enh_s.startswith("5.1."):
            return "rejected", "mailbox_not_found"
        if enh_s in ("5.2.1",):
            return "rejected", "mailbox_disabled"
        if enh_s in ("5.2.2",) or code == 552 and re.search(r"quota|full", t, re.I):
            return "rejected", "mailbox_full"
        if USER_RE.search(t):
            return "rejected", "mailbox_not_found"
        if enh_s and enh_s.startswith("5.7.") or BLOCK_RE.search(t):
            return "blocked", "smtp_blocked"
        if code in (550, 551, 553):
            return "rejected", "mailbox_rejected"
        return "ambiguous", "smtp_rejected_unclear"
    return "ambiguous", "smtp_unexpected_reply"


def _resolvable(name):
    try:
        r = dns.resolver.Resolver()
        r.lifetime = 4
        r.resolve(name, "A")
        return True
    except Exception:
        return False


class Verifier:
    def __init__(self, helo=None, mail_from=None, proxy=None, timeout=12.0, check_catch_all=True, smtp=True,
                 workers=8, ipv6=True, log=None, proxy_groups=None, allow_direct=False):
        self.helo = helo or os.environ.get("EMAILVERIF_HELO") or socket.getfqdn() or "localhost"
        if "." not in self.helo or self.helo.endswith(".localdomain") or self.helo.endswith(".local"):
            self.helo = "mail.example.org" if not helo else helo
        self.mail_from = mail_from or os.environ.get("EMAILVERIF_FROM") or f"verify@{self.helo}"
        if self.mail_from in ("<>", "null", "none"):
            self.mail_from = ""
        elif self.mail_from.endswith("@" + self.helo) and not _resolvable(self.helo):
            # nome da máquina sem DNS público (ex.: executor do Actions): o remetente vazio (<>, o dos avisos
            # de entrega) evita o "Sender address rejected: Domain not found" (kernel.org e outros, 23/11/2026)
            self.mail_from = ""
        self.proxy = proxy
        self.proxy_groups = set(proxy_groups or [])   # vazio = o proxy serve todos os grupos
        self.allow_direct = allow_direct               # porta 25 direta: só onde for permitido (Actions)
        self.timeout = timeout
        self.check_catch_all = check_catch_all
        self.smtp = smtp
        self.workers = workers
        self.ipv6 = ipv6
        self.dns = DNS()
        self.catch = {}          # domínio -> True/False/None
        self.last_conn = {}      # grupo -> hora da última conexão
        self.group_locks = {}
        self.lock = threading.Lock()
        self.smtp_conns = 0
        self.smtp_bytes = 0
        self.log = log or (lambda *a: None)
        self.emit = None          # função chamada com cada resultado final
        self.hold_temp = False    # True na 1ª volta: resposta temporária espera a nova tentativa
        self.http_proxy = None    # proxy HTTP(S)/SOCKS para a consulta do Yahoo
        self.yahoo = None
        self.microsoft = None

    # ---- um e-mail sem SMTP
    def pre(self, raw):
        t0 = time.time()
        email = normalize(raw)
        it = {"email": email, "status": None, "reason": None, "reasonText": None, "isValidSyntax": False,
              "localPart": None, "domain": None, "mxFound": None, "mxHosts": [], "provider": None,
              "isFreeProvider": None, "isDisposable": None, "isRole": None, "isCatchAll": None,
              "smtpCode": None, "smtpEnhancedCode": None, "smtpMessage": None, "didYouMean": None,
              "checkMs": None, "checkedAt": None}
        ok, local, dom, why = syntax(email)
        it["localPart"], it["domain"] = local, dom
        if not ok:
            it.update(status="invalid", reason="invalid_syntax", reasonText=why)
            return self._fim(it, t0), None
        email = f"{local}@{dom}"
        it["email"] = email
        it["isValidSyntax"] = True
        it["isRole"] = local.lower().split("+")[0] in ROLE
        it["isFreeProvider"] = dom in FREE
        it["isDisposable"] = is_disposable(dom)
        it["didYouMean"] = did_you_mean(local, dom)
        st, val = self.dns.mx(dom)
        if st != "ok":
            it["mxFound"] = False if st != "dns_error" else None
            if st == "dns_error":
                it.update(status="unknown", reason="dns_error", reasonText=val)
            else:
                it.update(status="invalid", reason={"nxdomain": "domain_not_found", "no_mx": "no_mx",
                                                    "null_mx": "null_mx"}[st], reasonText=val)
            return self._fim(it, t0), None
        it["mxFound"] = True
        it["mxHosts"] = val[:3]
        it["provider"] = provider_of(val[0], dom)
        if it["isDisposable"]:
            it.update(status="disposable", reason="disposable_domain",
                      reasonText="Domain is on the open disposable-email list (github.com/disposable-email-domains)")
            return self._fim(it, t0), None
        it["_pre_ms"] = (time.time() - t0) * 1000
        if not self.smtp:
            it.update(status="role" if it["isRole"] else "unknown", reason="smtp_check_off",
                      reasonText="SMTP check turned off: only syntax, MX, disposable and role were checked")
            if it["isRole"]:
                it["reason"] = "role_address"
            return self._fim(it, t0), None
        return it, (t0, val)

    @staticmethod
    def _fim(it, t0):
        it["checkMs"] = int((time.time() - t0) * 1000)
        it["checkedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return it

    # ---- SMTP de um grupo de domínios que usam os mesmos servidores
    def _wait_turn(self, group):
        with self.lock:
            lk = self.group_locks.setdefault(group, threading.Lock())
        lk.acquire()
        with self.lock:
            last = self.last_conn.get(group, 0)
        espera = PAUSA_CONEXAO - (time.time() - last)
        if espera > 0:
            time.sleep(espera)
        return lk

    def _done_turn(self, group, lk):
        with self.lock:
            self.last_conn[group] = time.time()
        lk.release()

    def _smtp_domain(self, dom, hosts, items):
        """items: lista de (it, t0). Preenche cada it. Devolve os que tiveram resposta temporária."""
        temp = []
        pend = list(items)
        group = mx_group(hosts[0])
        one = hosts[0].endswith("olc.protection.outlook.com")
        proxy = self.proxy if (self.proxy and (not self.proxy_groups or group in self.proxy_groups)) else None
        if proxy is None and not self.allow_direct:
            for it, t0 in items:
                it.update(status="unknown", reason="no_smtp_exit",
                          reasonText="No SMTP exit configured for this mail provider, so the mailbox was not checked")
                self._fim(it, t0)
                self._emit(it)
            return []
        precisa_catch = self.check_catch_all and dom not in self.catch
        while pend:
            lote, pend = pend[:RCPT_POR_CONEXAO], pend[RCPT_POR_CONEXAO:]
            lk = self._wait_turn(group)
            conv = None
            erro = None
            try:
                for h in hosts[:3]:
                    conv = Conversa(h, self.helo, self.mail_from, self.timeout, proxy, self.ipv6)
                    try:
                        _conn_slot()
                        with self.lock:
                            self.smtp_conns += 1
                        t_open = time.time()
                        conv.open()
                        conn_ms = (time.time() - t_open) * 1000
                        erro = None
                        break
                    except SMTPError as e:
                        erro = e
                        conv.close()
                        if len(e.args) > 1 and 500 <= (e.args[1] or 0) < 600:
                            break  # recusa de política: outro MX do mesmo domínio dá o mesmo
                    except (OSError, ssl.SSLError) as e:
                        erro = e
                        conv.close()
                        if isinstance(e, (socket.timeout, TimeoutError)) and h != hosts[0]:
                            break  # dois MX sem resposta: não insiste no terceiro
                if erro is not None:
                    for it, t0 in lote:
                        self._smtp_fail(it, t0, erro)
                        if it["reason"] in TEMP_REASONS:
                            temp.append((it, t0))
                    continue
                if precisa_catch:
                    rnd = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(14))
                    try:
                        c, t = conv.rcpt(f"{rnd}@{dom}", one)
                        k, _ = classify(c, t)
                        self.catch[dom] = True if k == "accepted" else (False if k == "rejected" else None)
                        self.log(f"catch-all {dom}: {c} {t[:80]} -> {self.catch[dom]}")
                    except Exception as e:
                        self.catch[dom] = None
                    precisa_catch = False
                    time.sleep(PAUSA_RCPT)
                for i, (it, t0) in enumerate(lote):
                    try:
                        t_r = time.time()
                        c, t = conv.rcpt(it["email"], one)
                        t0 = time.time() - (it.get("_pre_ms", 0) + (conn_ms if i == 0 else 0)) / 1000 - (time.time() - t_r)
                    except (OSError, SMTPError, ssl.SSLError) as e:
                        # conexão caiu no meio: o resto volta para a fila uma vez
                        resto = lote[i:]
                        for it2, t02 in resto:
                            it2.setdefault("_retry_conn", 0)
                        if all(x[0]["_retry_conn"] == 0 for x in resto):
                            for x in resto:
                                x[0]["_retry_conn"] = 1
                            pend = resto + pend
                        else:
                            for it2, t02 in resto:
                                self._smtp_fail(it2, t02, e)
                                if it2["reason"] in TEMP_REASONS:
                                    temp.append((it2, t02))
                        break
                    self._smtp_result(it, t0, c, t, dom)
                    if it["status"] == "unknown" and it["reason"] in TEMP_REASONS:
                        temp.append((it, t0))
                    if c == 421:
                        resto = lote[i + 1:]
                        for x in resto:
                            temp.append(x)
                            self._smtp_fail(x[0], x[1], SMTPError(f"421 {t[:120]}", 421, t))
                        break
                    time.sleep(PAUSA_RCPT)
                try:
                    conv.cmd("RSET")
                except Exception:
                    pass
            finally:
                if conv is not None:
                    with self.lock:
                        self.smtp_bytes += conv.bytes
                    conv.close()
                self._done_turn(group, lk)
                for it, _ in lote:
                    if it["status"] is not None and not (self.hold_temp and it["reason"] in TEMP_REASONS):
                        self._emit(it)
        return temp

    def _emit(self, it):
        with self.lock:
            if it.get("_emitted"):
                return
            it["_emitted"] = True
        it.pop("_retry_conn", None)
        it.pop("_pre_ms", None)
        it.pop("_lookup", None)
        if self.emit:
            self.emit(it)

    def _smtp_fail(self, it, t0, e):
        txt = str(e.args[0]) if isinstance(e, SMTPError) and e.args else f"{type(e).__name__}: {e}"
        code = e.args[1] if isinstance(e, SMTPError) and len(e.args) > 1 else None
        if isinstance(e, (socket.timeout, TimeoutError)):
            reason, rt = "smtp_timeout", "The mail server did not answer in time"
        elif isinstance(e, ConnectionRefusedError):
            reason, rt = "smtp_unreachable", "The mail server refused the connection on port 25"
        elif isinstance(e, OSError) and not isinstance(e, SMTPError):
            reason, rt = "smtp_unreachable", f"Could not connect to the mail server on port 25 ({txt[:80]})"
        elif txt.startswith("SOCKS5"):
            reason, rt = "proxy_error", "The SMTP exit (proxy) failed to reach the mail server"
        elif code and 400 <= code < 500:
            reason, rt = "temporary_error", "The mail server asked to try again later"
        elif code and 500 <= code < 600:
            reason, rt = "smtp_blocked", "The mail server refused the verification connection (sender policy)"
        else:
            reason, rt = "smtp_error", "The SMTP conversation failed"
        it.update(status="unknown", reason=reason, reasonText=rt, smtpCode=code, smtpMessage=txt[:200])
        self._fim(it, t0)

    def _smtp_result(self, it, t0, code, text, dom):
        kind, reason = classify(code, text)
        enh = ENH_RE.search(text or "")
        it.update(smtpCode=code, smtpEnhancedCode=enh.group(0) if enh else None, smtpMessage=(text or "")[:200])
        ca = self.catch.get(dom)
        it["isCatchAll"] = ca
        mx0 = (self.dns.cache.get(dom, ("", [""]))[1] or [""])[0]
        if kind == "accepted" and str(mx0).endswith("olc.protection.outlook.com"):
            it.update(status="unknown", reason="microsoft_unconfirmed",
                      reasonText="Outlook.com/Hotmail accepted the address, but its server also accepts some addresses "
                                 "that do not exist, so this is unconfirmed (the Microsoft account lookup was unavailable)")
        elif kind == "accepted":
            if ca:
                it.update(status="catch_all", reason="catch_all_domain",
                          reasonText="The server accepts any address on this domain, so this mailbox cannot be confirmed")
            elif it["isRole"]:
                it.update(status="role", reason="role_address",
                          reasonText="Mailbox exists, but it is a role/group address (info@, contact@...)")
            else:
                it.update(status="valid", reason="mailbox_exists", reasonText="The mail server accepted this mailbox")
                if ca is None and self.check_catch_all:
                    it["reasonText"] += " (catch-all test was inconclusive)"
        elif kind == "rejected":
            it.update(status="invalid", reason=reason, reasonText={
                "mailbox_not_found": "The mail server says this mailbox does not exist",
                "mailbox_disabled": "The mailbox is disabled",
                "mailbox_full": "The mailbox is over quota and will bounce",
                "mailbox_rejected": "The mail server rejected this mailbox"}[reason])
        elif kind == "blocked":
            it.update(status="unknown", reason=reason,
                      reasonText="The mail server refused to answer for this address (anti-spam policy), so it is unconfirmed")
        elif kind == "temp":
            it.update(status="unknown", reason=reason, reasonText={
                "smtp_timeout": "The mail server did not answer in time",
                "proxy_error": "The SMTP exit (proxy) failed",
                "greylisted": "Greylisted: the server asked to try again later",
                "too_many_recipients": "The server limited recipients per connection",
                "temporary_error": "Temporary error from the mail server"}[reason])
        else:
            it.update(status="unknown", reason=reason, reasonText="The mail server did not confirm or deny this mailbox")
        self._fim(it, t0)

    def run_smtp(self, pend):
        """pend: lista de (it, (t0, hosts)). Agrupa por domínio e por grupo de MX; grupos em paralelo."""
        por_grupo = {}
        for it, (t0, hosts) in pend:
            g = mx_group(hosts[0])
            por_grupo.setdefault(g, {}).setdefault(it["domain"], (hosts, []))[1].append((it, t0))
        temp = []

        def faz(g):
            out = []
            for dom, (hosts, items) in por_grupo[g].items():
                out += self._smtp_domain(dom, hosts, items)
            return out

        with ThreadPoolExecutor(max_workers=max(1, min(self.workers, len(por_grupo)))) as ex:
            for r in ex.map(faz, list(por_grupo)):
                temp += r
        return temp

    def _lookup(self, lista, pend, fn, nome, nota, stop):
        """Consulta por HTTPS (Yahoo, Microsoft). Sem resposta: o e-mail vai para o SMTP."""
        for it, p in lista:
            if stop and stop():
                return
            t0 = time.time()
            ex, code = fn(it)
            if ex is None:
                it["_lookup"] = f"{nome}: {code}"
                pend.append((it, p))
                continue
            it.update(smtpMessage=f"{nome} account lookup: {code or 'available'}")
            if nome == "Yahoo":
                it["isCatchAll"] = True
            if ex:
                if it["isRole"]:
                    it.update(status="role", reason="role_address",
                              reasonText=f"{nome} account exists, but it is a role/group address")
                else:
                    it.update(status="valid", reason="mailbox_exists", reasonText=f"{nome} says this account exists ({nota})")
            else:
                it.update(status="invalid", reason="mailbox_not_found", reasonText=f"{nome} says no account has this address ({nota})")
            self._fim(it, t0 - it.get("_pre_ms", 0) / 1000)
            self._emit(it)

    def verify_all(self, raws, greylist_wait=60, yahoo=True, stop=None):
        """Verifica a lista; cada resultado final sai por self.emit(it) assim que fica pronto.
        stop(): função que, se devolver True, interrompe (teto de custo)."""
        t_start = time.time()
        pend, yah, ms = [], [], []
        for raw in raws:
            if stop and stop():
                return
            it, p = self.pre(raw)
            if p is None:
                self._emit(it)
            elif yahoo and it["domain"] == "yahoo.com":
                yah.append((it, p))
            elif yahoo and mx_group(p[1][0]) == "outlook.com":
                ms.append((it, p))
            else:
                pend.append((it, p))
        if yah:
            self.yahoo = self.yahoo or YahooAPI(proxy=self.http_proxy)
            self._lookup(yah, pend, lambda it: self.yahoo.exists(it["localPart"]), "Yahoo",
                         "Yahoo's SMTP accepts every address, so the account lookup decides", stop)
        if ms:
            self.microsoft = self.microsoft or MicrosoftAPI(proxy=self.http_proxy)
            self._lookup(ms, pend, lambda it: self.microsoft.exists(it["email"]), "Microsoft",
                         "checked on the Microsoft sign-in lookup", stop)
        if stop and stop():
            return
        self.hold_temp = greylist_wait > 0
        temp = self.run_smtp(pend) if pend else []
        hosts = {it["domain"]: p[1] for it, p in pend}
        if temp and greylist_wait > 0 and not (stop and stop()):
            espera = greylist_wait - (time.time() - t_start)
            self.log(f"{len(temp)} e-mails com resposta temporária; nova tentativa em {max(0, int(espera))} s")
            if espera > 0:
                time.sleep(espera)
            self.hold_temp = False
            por = {}
            for it, _ in temp:
                if not it.get("_emitted"):
                    por.setdefault(it["domain"], []).append((it, time.time()))
            for dom, items in por.items():
                for it, _ in items:
                    it.pop("_retry_conn", None)
                    it["retried"] = True
                self._smtp_domain(dom, hosts[dom], items)
        for it, _ in temp:
            self._emit(it)


# --- Yahoo (yahoo.com) --------------------------------------------------------------------------------------
# O servidor SMTP do Yahoo aceita qualquer endereço no RCPT TO (testado em 23/11/2026: 250 para um inventado),
# então o SMTP não decide. A página de cadastro do Yahoo diz se o nome de usuário já existe
# (o mesmo caminho do reacherhq/check-if-email-exists, core/src/smtp/yahoo/api.rs). Só vale para @yahoo.com.

class YahooAPI:
    SIGN = ("https://login.yahoo.com/account/create?lang=en-US&src=ym&done=https%3A%2F%2Fmail.yahoo.com%2F"
            "&specId=yidregsimplified")
    VAL = SIGN.replace("/account/create?", "/account/create/validate?") + "&validateField=userId"

    def __init__(self, proxy=None, pause=1.0):
        self.proxy, self.pause = proxy, pause
        self.s = None
        self.form = None
        self.used = 0
        self.calls = 0
        self.bytes = 0
        self.last = 0
        self.fails = 0
        self.lock = threading.Lock()

    def _session(self):
        from curl_cffi import requests
        self.s = requests.Session(impersonate="chrome", proxy=self.proxy) if self.proxy else requests.Session(impersonate="chrome")
        r = self.s.get(self.SIGN, timeout=20)
        self.calls += 1
        self.bytes += len(r.content)

        def hid(n):
            m = re.search(r'<input[^>]*\bname="%s"[^>]*>' % n, r.text)
            v = re.search(r'\bvalue="([^"]*)"', m.group(0)) if m else None
            return v.group(1) if v else None
        acrumb, sidx = hid("acrumb"), hid("sessionIndex")
        if not acrumb or not sidx or "AS" not in self.s.cookies.keys():
            raise SMTPError("Yahoo sign-up page without session")
        self.form = {"acrumb": acrumb, "crumb": hid("crumb") or "", "sessionIndex": sidx,
                     "specId": "yidregsimplified", "yidDomain": "yahoo.com"}
        self.used = 0

    def exists(self, local):
        """True / False / None (não deu para saber)"""
        with self.lock:
            if self.fails >= 3:
                return None, "yahoo_lookup_off"
            for tentativa in range(2):
                try:
                    if self.s is None or self.used >= 25 or tentativa:
                        self._session()
                    espera = self.pause - (time.time() - self.last)
                    if espera > 0:
                        time.sleep(espera)
                    r = self.s.post(self.VAL, data={**self.form, "userId": local}, timeout=20, headers={
                        "Origin": "https://login.yahoo.com", "Referer": self.SIGN, "X-Requested-With": "XMLHttpRequest",
                        "Accept": "*/*"})
                    self.last = time.time()
                    self.calls += 1
                    self.used += 1
                    self.bytes += len(r.content)
                    d = r.json()
                    if "fields" not in d:
                        continue
                    err = (d["fields"].get("userId") or {}).get("error")
                    self.fails = 0
                    if not err:
                        return False, None
                    if err.get("id") in ("IDENTIFIER_EXISTS", "IDENTIFIER_NOT_AVAILABLE"):
                        return True, err.get("id")
                    return None, err.get("id")
                except Exception as e:
                    self.s = None
                    err = f"{type(e).__name__}"
            self.fails += 1
            return None, "yahoo_lookup_failed"


def forbidden_host():
    """Máquinas onde a porta 25 direta é proibida (a VPS do ecossistema: docs/incidentes.md, 23/11/2026 18:42).
    Lista em EMAILVERIF_FORBIDDEN_HOSTS (vírgulas) somada ao nome da VPS."""
    nomes = {"srv2118426", "srv2118426.hstgr.cloud"}
    nomes.update(x.strip() for x in (os.environ.get("EMAILVERIF_FORBIDDEN_HOSTS") or "").split(",") if x.strip())
    h = socket.gethostname().lower()
    return h in nomes or socket.getfqdn().lower() in nomes or os.path.exists("/opt/money-video/ferramentas/pom-robos")


# --- Microsoft (Outlook.com/Hotmail e Microsoft 365) --------------------------------------------------------
# O SMTP do Outlook.com/Hotmail não é confiável para o "existe": em 23/11/2026 um endereço inventado
# @outlook.com voltou "250 2.1.5 Recipient OK" (Actions, Azure) e outro @hotmail.com também (VPS), enquanto
# outros inventados voltaram 550 5.5.0. O "não existe" (550) bateu sempre. A tela de login da Microsoft diz se
# a conta existe: POST login.microsoftonline.com/common/GetCredentialType -> IfExistsResult
# (0 = existe numa organização, 5/6 = existe como conta pessoal, 1 = não existe). Testado em 23/11/2026:
# noahwang.wang@outlook.com 5, inventado @outlook.com 1, inventado @hotmail.com 1, decui@microsoft.com 0,
# inventado @microsoft.com 1. DomainType 4 (domínio federado, com login em outro provedor) não decide.

class MicrosoftAPI:
    URL = "https://login.microsoftonline.com/common/GetCredentialType"

    def __init__(self, proxy=None, pause=1.0):
        self.proxy, self.pause = proxy, pause
        self.s = None
        self.calls = 0
        self.bytes = 0
        self.last = 0
        self.fails = 0
        self.lock = threading.Lock()

    def exists(self, email):
        """(True/False/None, nota)"""
        with self.lock:
            if self.fails >= 3:
                return None, "microsoft_lookup_off"
            try:
                if self.s is None:
                    from curl_cffi import requests
                    self.s = requests.Session(impersonate="chrome", proxy=self.proxy) if self.proxy else requests.Session(impersonate="chrome")
                espera = self.pause - (time.time() - self.last)
                if espera > 0:
                    time.sleep(espera)
                r = self.s.post(self.URL, timeout=20, json={
                    "username": email, "isOtherIdpSupported": True, "checkPhones": False, "isRemoteNGCSupported": True,
                    "isCookieBannerShown": False, "isFidoSupported": True, "originalRequest": "", "forceotclogin": False,
                    "isExternalFederationDisallowed": False, "isRemoteConnectSupported": False, "federationFlags": 0,
                    "isSignup": False, "flowToken": "", "isAccessPassSupported": True})
                self.last = time.time()
                self.calls += 1
                self.bytes += len(r.content)
                d = r.json()
            except Exception as e:
                self.fails += 1
                self.s = None
                return None, f"microsoft_lookup_failed ({type(e).__name__})"
            self.fails = 0
            if d.get("ThrottleStatus") == 1:
                return None, "microsoft_lookup_throttled"
            dt = (d.get("EstsProperties") or {}).get("DomainType")
            res = d.get("IfExistsResult")
            if dt == 4 or d.get("Credentials", {}).get("FederationRedirectUrl"):
                return None, "federated_domain"
            if res in (0, 5, 6):
                return True, f"IfExistsResult={res}"
            if res == 1:
                return False, "IfExistsResult=1"
            return None, f"IfExistsResult={res}"
