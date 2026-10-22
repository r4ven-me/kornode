"""Stdlib-only root worker, sent as fixed Python source over pinned SSH.

Never import application code on the VM host. All kernel tests run inside owned
Docker network namespaces. No generic exec/upload/delete endpoint is exposed.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

BASE = Path("/var/lib/kornode-e2e")
MARKER = Path("/etc/kornode-e2e-vm.json")
CASES = {
    "enroll",
    "change",
    "blackhole",
    "revoke",
    "restore",
    "upgrade",
    "cache",
    "route",
    "rollback",
    "tamper",
    "routed",
}
ROLES = {"hub", "agent-a", "agent-b", "ext"}
ACCESS_PORT = 8443  # published by agent-a in case `routed`
# NL-06: the "source" network of agent-b (node 3, default source pool 10.8.<id>.0/24):
# the node container is 10.8.3.2, the throwaway client container 10.8.3.20.
SOURCE_CIDR = "10.8.3.0/24"
SOURCE_NODE_ADDRESS = "10.8.3.2"
SOURCE_CLIENT_ADDRESS = "10.8.3.20"
# E2E-07 (spec edition): the same shape on the hub, standing in for an attached wg-easy.
HUB_SOURCE_CIDR = "10.8.1.0/24"
HUB_SOURCE_NODE_ADDRESS = "10.8.1.2"
HUB_SOURCE_CLIENT_ADDRESS = "10.8.1.20"
# NL-05: a real wg-easy (AmneziaWG, userspace implementation) is the source of agent-a. It shares
# the node container's network namespace, so `wg0` lives where the node's policy applies.
AWG_IMAGE = "ghcr.io/wg-easy/wg-easy:15.4.0"
AWG_PORT = 51820
AWG_SOURCE_CIDR = "10.8.2.0/24"  # agent-a is node 2: its source network is 10.8.<id>.0/24
IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*(?:@sha256:[0-9a-f]{64})?$")

PROXY = """import select, socket, socketserver
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  with socket.create_connection(("10.99.0.1",8444),timeout=5) as upstream:
   self.request.settimeout(5)
   while True:
    ready,_,_=select.select([self.request,upstream],[],[],90)
    if not ready: return
    for src in ready:
     data=src.recv(65536)
     if not data: return
     (upstream if src is self.request else self.request).sendall(data)
class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True
with Server(("0.0.0.0",18444),Handler) as server: server.serve_forever()
"""
# Runs inside the wg-easy container: wait for its API, switch its NAT/FORWARD hooks off (kornode
# owns NAT for the source, D-68), create the client and print its configuration.
AWG_API = """const o=process.env, base="http://127.0.0.1:"+o.PORT;
const auth="Basic "+Buffer.from(o.INIT_USERNAME+":"+o.INIT_PASSWORD).toString("base64");
async function call(method,path,body){
 const headers={Authorization:auth,"Content-Type":"application/json"};
 const r=await fetch(base+path,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 const text=await r.text();
 if(!r.ok) throw new Error(method+" "+path+" "+r.status);
 return text;
}
(async()=>{
 for(let i=0;;i++){
  try{ await call("GET","/api/admin/hooks"); break }
  catch(e){ if(i>=90) throw e; await new Promise(r=>setTimeout(r,1000)) }
 }
 await call("POST","/api/admin/hooks",{preUp:"",postUp:"",preDown:"",postDown:""});
 const made=JSON.parse(await call("POST","/api/client",{name:"awg3",expiresAt:null}));
 const config=await call("GET","/api/client/"+made.clientId+"/configuration");
 console.log(JSON.stringify({config}));
})().catch(e=>{console.error(e.message);process.exit(1)});
"""
AWG_CONNECT = """const o=JSON.parse(require("fs").readFileSync(0,"utf8"));
const s=require("net").connect({host:o.host,port:o.port,timeout:3000});
s.on("connect",()=>{console.log(JSON.stringify({ok:true}));s.destroy()});
const fail=()=>{console.log(JSON.stringify({ok:false}));s.destroy()};
s.on("error",fail);s.on("timeout",fail);
"""
PROBE = """import http.client, json, ssl, subprocess, sys
from pathlib import Path
from urllib.parse import urlsplit
import yaml
root=Path("/var/lib/kornode-agent")
ctx=ssl.create_default_context(cafile=str(root/"tls/ca.pem"))
ctx.load_cert_chain(str(root/"tls/cert.pem"), str(root/"tls/key.pem"))
options=json.load(sys.stdin)
try:
 if options.get("gateway"):
  # Test-only TCP relay preserves mTLS/CA validation but changes the dial hostname.
  # It is not the production control listener and never disables chain validation.
  ctx.check_hostname=False
  host,port,source=options["gateway"],18444,None
 else:
  cfg=yaml.safe_load((root/"agent.yaml").read_text())
  url=urlsplit(cfg["hub"]["control_url"])
  link=json.loads(subprocess.check_output(["ip","-j","addr","show","dev","oc-hub0"]))
  ip=next(a["local"] for d in link for a in d["addr_info"] if a["family"]=="inet")
  host,port,source=url.hostname,url.port,(ip,0)
 conn=http.client.HTTPSConnection(host,port,context=ctx,source_address=source,timeout=3)
 conn.request("GET","/agent/v1/ping")
 response=conn.getresponse()
 print(json.dumps({"status":response.status}))
 conn.close()
except Exception: print(json.dumps({"status":0}))
"""
ENROLL = """import sys
from kornode_agent.cli import main
raise SystemExit(main(["enroll",sys.stdin.read(),"--json"]))
"""
EXT_USER = """import json, os, sys
from kornode.config.loader import load_config
from kornode.services.users import UserService
value=json.load(sys.stdin)
result=UserService(load_config(os.environ["KORNODE_CONFIG"])).create_user("e2e",value["password"])
raise SystemExit(0 if result.ok else 1)
"""
WATCHDOG = """import subprocess, sys, time
time.sleep(60)
container=sys.argv[1]
# Immutable container ID: never touches a later run or any host nft table.
subprocess.run(["docker","--host","unix:///var/run/docker.sock","exec",container,"nft","delete","table","inet","kn_e2e_fault"],
 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
"""
REPAIR_ROUTE = """import json,time
from kornode.net.kernel import Kernel
from kornode.net.diff import Plan, DelRoute
kernel=Kernel()
route=next(r for r in kernel.read().routes if r.dev=="oc-hub0" and r.type=="unicast")
started=time.monotonic()
kernel.apply(Plan((DelRoute(route),)))
restored=False
while time.monotonic()-started<=2:
 if route in kernel.read().routes:
  restored=True
  break
 time.sleep(.05)
print(json.dumps({"restored":restored,"seconds":time.monotonic()-started}))
"""
INJECT_BUNDLE = """import hashlib,json,os,sys,time
from contextlib import closing
from kornode.config.loader import load_config
from kornode.registry.db import open_registry,transaction
from kornode.registry.repository import Registry
from kornode.services.bundle import BundleService
from kornode.bundle.canonical import canonical_json,body_sha256
from kornode.bundle.signing import sign,key_id
from kornode.bundle.validator import validate
options=json.load(sys.stdin)
config=load_config(os.environ["KORNODE_CONFIG"])
with closing(open_registry(config.system.data_dir/"registry.db")) as conn, transaction(conn):
 registry=Registry(conn)
 node=registry.get_node_by_name("agent-a")
 latest=registry.latest_bundle(node.id)
 version=max(latest.version,node.desired_version,node.high_water_version)+1
 body=json.loads(latest.body)
 body["version"]=version
 if not options["tamper"]: body["hubs"][0]["port"]=1
 wire=canonical_json(body)
 key=BundleService(config).signing_key(registry)
 signature=sign(wire,key)
 validate(wire,signature,trusted={key_id(key.public_key()):key.public_key()},
          high_water_version=version-1,agent_version=config.control.min_agent_version,
          expected_node_id=node.id)
 if options["tamper"]: wire+=b" "
 registry.add_bundle(node_id=node.id,version=version,body=wire,signature=signature,
  sha256=body_sha256(wire),content_hash=hashlib.sha256(wire).hexdigest(),
  key_id=key_id(key.public_key()),reason="test-only injected fault")
 registry.update_node(node.id,desired_version=version)
print(json.dumps({"version":version}))
"""
LISTEN = """import json,socket,sys
options=json.load(sys.stdin)
server=socket.socket()
server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
server.bind(("0.0.0.0",options["port"]))
server.listen(4)
server.settimeout(options["seconds"])
try:
 conn,peer=server.accept()
 conn.close()
 print(json.dumps({"peer":peer[0]}))
except socket.timeout:
 print(json.dumps({"peer":None}))
"""
CONNECT = """import json,socket,sys
options=json.load(sys.stdin)
try:
 source=(options["source"],0) if options.get("source") else None
 socket.create_connection((options["host"],options["port"]),timeout=3,source_address=source).close()
 print(json.dumps({"ok":True}))
except OSError:
 print(json.dumps({"ok":False}))
"""
# Throwaway VPN client (P4-04, NL-03) in its own container of the agent-b VM, so the
# `kornode.net` policy of agent-b does not touch the outer connection. The tunnel
# gets the listed routes only.
ACCESS_CLIENT = """import json,os,subprocess,sys,time
o=json.load(sys.stdin)
d="/tmp/kn-access"
os.makedirs(d,exist_ok=True)
gw=None
if o.get("full"):
 r=subprocess.run(["ip","-4","-j","route","show","default"],capture_output=True)
 gw=json.loads(r.stdout)[0]["gateway"]
script="\\n".join([
 "#!/bin/sh",
 '[ "$reason" = connect ] || exit 0',
 'ip link set dev "$TUNDEV" up mtu "${INTERNAL_IP4_MTU:-1400}"',
 'ip addr add "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV"',
 *["ip route add %s dev \\"$TUNDEV\\""%r for r in o["routes"]],
 *(["ip route add %s/32 via %s"%(o["host"],gw)] if gw else []),
 *(['ip route replace default dev "$TUNDEV"'] if gw else []),
 ""])
open(d+"/vpnc","w").write(script)
os.chmod(d+"/vpnc",0o755)
url="https://%s:%d"%(o["host"],o["port"])
subprocess.run(["openconnect","--background","--pid-file="+d+"/pid",
 "--interface","kn-vpnc0","--script="+d+"/vpnc","--servercert",o["pin"],
 "--non-inter","--user",o["user"],"--passwd-on-stdin",url],
 input=(o["password"]+"\\n").encode(),stdout=open(d+"/log","ab"),
 stderr=subprocess.STDOUT,timeout=60,check=True)
addr=None
for _ in range(150):
 r=subprocess.run(["ip","-4","-j","addr","show","dev","kn-vpnc0"],capture_output=True)
 if r.returncode==0 and json.loads(r.stdout)[0]["addr_info"]:
  addr=json.loads(r.stdout)[0]["addr_info"][0]["local"];break
 time.sleep(0.2)
if addr is None: raise SystemExit("no tunnel address")
print(json.dumps({"address":addr}))
"""
ACCESS_CLIENT_STOP = """import os,signal
try:
 os.kill(int(open("/tmp/kn-access/pid").read()),signal.SIGTERM)
except (OSError,ValueError): pass
"""
# One A query to the agent's resolver (stdlib only; the agent image has no dig).
RESOLVE = """import json,random,socket,struct,sys
o=json.load(sys.stdin)
q=random.randrange(65536)
n=b"".join(bytes([len(p)])+p.encode() for p in o["name"].split("."))+b"\\0"
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(3)
try:
 s.sendto(struct.pack("!6H",q,256,1,0,0,0)+n+struct.pack("!2H",1,1),(o["server"],53))
 d=s.recv(4096)
except OSError:
 print(json.dumps({"address":None,"rcode":None}));sys.exit()
i,f,qd,an,_,_=struct.unpack("!6H",d[:12])
p=12+len(n)+4
a=None
for _ in range(an if i==q else 0):
 while d[p]&192!=192 and d[p]:p+=d[p]+1
 p+=2 if d[p]&192==192 else 1
 t,c,_,l=struct.unpack("!2HIH",d[p:p+10]);p+=10
 if t==1 and l==4:a=socket.inet_ntoa(d[p:p+4]);break
 p+=l
print(json.dumps({"address":a,"rcode":f&15}))
"""
IDENTITY = """import hashlib,json
from pathlib import Path
p=Path("/var/lib/kornode-agent")
print(json.dumps({"certificate":hashlib.sha256((p/"tls/cert.pem").read_bytes()).hexdigest()}))
"""


def atomic(path: Path, value: Any, mode: int = 0o600) -> None:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".e2e-")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class Worker:
    def __init__(
        self, request: dict[str, Any], *, base: Path = BASE, marker: Path = MARKER
    ) -> None:
        self.request = request
        self.base, self.marker = base, marker
        self.role, self.run_id, self.case = (
            request["role"],
            request["run_id"],
            request.get("case", ""),
        )
        if self.role not in ROLES or not re.fullmatch(r"[0-9a-f]{24}", self.run_id):
            raise ValueError("invalid identity")
        if self.case and self.case not in CASES:
            raise ValueError("invalid case")
        self.root = base / self.run_id
        self.directory = self.root / self.case if self.case else self.root
        self.payload = request.get("payload", {})
        self.machine_file = Path("/etc/machine-id")

    def guard(self, *, lease: bool = True) -> str:
        if os.geteuid() != 0:
            raise ValueError("root worker required")
        info = self.marker.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unsafe marker")
        machine = self.machine_file.read_text().strip()
        marker = json.loads(self.marker.read_text())
        if marker != {
            "purpose": "kornode-e2e-disposable",
            "role": self.role,
            "machine_id": machine,
        }:
            raise ValueError("VM not designated")
        if self.base.is_symlink() or (self.base.exists() and self.base.stat().st_mode & 0o022):
            raise ValueError("unsafe base")
        if lease:
            if self.root.is_symlink() or not self.root.is_dir():
                raise ValueError("missing owner root")
            path = self.base / "lease.json"
            if path.is_symlink() or json.loads(path.read_text()) != self.owner():
                raise ValueError("foreign lease")
        return hashlib.sha256(machine.encode()).hexdigest()

    def owner(self) -> dict[str, str]:
        return {"role": self.role, "run_id": self.run_id}

    def run(
        self,
        argv: list[str],
        *,
        data: bytes | None = None,
        allowed: tuple[int, ...] = (0,),
        timeout: int = 120,
    ) -> tuple[int, bytes]:
        if argv and argv[0] == "docker":
            argv = ["docker", "--host", "unix:///var/run/docker.sock", *argv[1:]]
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            result = subprocess.run(
                argv, input=data, stdout=out, stderr=err, timeout=timeout, check=False
            )
            if result.returncode not in allowed:
                raise ValueError("command failed; output withheld")
            out.seek(0)
            reply = out.read(12 * 1024 * 1024 + 1)
            if len(reply) > 12 * 1024 * 1024:
                raise ValueError("reply too large")
            return result.returncode, reply

    def compose(self, *args: str, **kwargs: Any) -> tuple[int, bytes]:
        return self.run(
            [
                "docker",
                "compose",
                "--project-name",
                self.project(),
                "--file",
                str(self.directory / "compose.json"),
                *args,
            ],
            **kwargs,
        )

    def project(self) -> str:
        return f"ke2e-{self.run_id[:12]}-{self.role}-{self.case}"

    def owned_case(self) -> dict[str, Any]:
        if not self.case or self.directory.is_symlink():
            raise ValueError("invalid case")
        path = self.directory / "owner.json"
        if path.is_symlink() or json.loads(path.read_text()) != self.owner():
            raise ValueError("foreign case")
        state = self.directory / "state.json"
        return json.loads(state.read_text()) if state.exists() else {}

    def container(self, service: str = "node") -> str:
        self.owned_case()
        container = self.compose("ps", "-a", "--quiet", service)[1].decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            raise ValueError("container missing")
        labels = json.loads(
            self.run(["docker", "inspect", "--format", "{{json .Config.Labels}}", container])[1]
        )
        expected = {
            "org.kornode.e2e.run": self.run_id,
            "org.kornode.e2e.role": self.role,
            "org.kornode.e2e.case": self.case,
        }
        if any(labels.get(key) != value for key, value in expected.items()):
            raise ValueError("foreign container")
        return container

    def execute(self, argv: list[str], **kwargs: Any) -> tuple[int, bytes]:
        return self.run(["docker", "exec", "-i", self.container(), *argv], **kwargs)

    def cli(self, *args: str, json_flag: bool = True, **kwargs: Any) -> Any:
        state = self.owned_case()
        flag = ["--json"] if json_flag else []  # `certificates pin` prints JSON, takes no flag
        raw = self.execute(["korctl", "--config", state["config"], *args, *flag], **kwargs)[1]
        return json.loads(raw)

    def preflight(self) -> dict[str, Any]:
        machine = self.guard(lease=False)
        if sys.version_info < (3, 12) or not stat.S_ISCHR(Path("/dev/net/tun").stat().st_mode):
            raise ValueError("missing prerequisites")
        if shutil.disk_usage(self.base.parent).free < 8 * 1024**3:
            raise ValueError("insufficient disk space")
        self.run(["docker", "info", "--format", "{{.ServerVersion}}"])
        self.run(["docker", "compose", "version"])
        if self.role in {"hub", "ext"}:
            for port in [443, 18444] if self.role == "hub" else [443]:
                with socket.socket() as sock:
                    sock.bind(("0.0.0.0", port))
        return {"machine": machine, "role": self.role, "python": list(sys.version_info[:2])}

    def claim(self) -> dict[str, bool]:
        self.guard(lease=False)
        self.base.mkdir(mode=0o700, exist_ok=True)
        # No stale-lease stealing: interruption requires explicit owner recovery.
        fd = os.open(
            self.base / "lease.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(self.owner(), handle)
                handle.flush()
                os.fsync(handle.fileno())
            self.root.mkdir(mode=0o700)
        except BaseException:
            (self.base / "lease.json").unlink(missing_ok=True)
            raise
        return {"claimed": True}

    def load_images(self, stream: BinaryIO) -> dict[str, bool]:
        size = self.payload["size"]
        if type(size) is not int or not 0 < size <= 3 * 1024**3:
            raise ValueError("invalid image size")
        with tempfile.TemporaryFile(dir=self.root) as handle:
            remaining = size
            while remaining:
                chunk = stream.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError("truncated image")
                handle.write(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                raise ValueError("trailing image data")
            handle.seek(0)
            with tempfile.TemporaryFile() as out:
                result = subprocess.run(
                    ["docker", "--host", "unix:///var/run/docker.sock", "load"],
                    stdin=handle,
                    stdout=out,
                    stderr=out,
                    timeout=500,
                    check=False,
                )
                if result.returncode:
                    raise ValueError("image load failed")
        return {"loaded": True}

    def image(self, value: str) -> str:
        if not isinstance(value, str) or not IMAGE_RE.fullmatch(value):
            raise ValueError("invalid image")
        identifier = (
            self.run(["docker", "image", "inspect", "--format", "{{.Id}}", value])[1]
            .decode()
            .strip()
        )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", identifier):
            raise ValueError("invalid image identity")
        return identifier

    def deploy(self) -> dict[str, str]:
        if not self.case:
            raise ValueError("missing case")
        image = self.payload["image"]
        identifier = self.image(image)
        self.directory.mkdir(mode=0o711)
        atomic(self.directory / "owner.json", self.owner())
        config_path = self.directory / "config.json"
        if self.role == "hub" and self.case == "routed":
            # The hub rewrites its own config (`source add`, `egress set`); the case directory
            # is mounted read-only, so the file lives in a writable bucket of its own.
            (self.directory / "config").mkdir(mode=0o700)
            config_path = self.directory / "config" / "config.json"
        state = {"config": str(config_path), "image": image}
        atomic(self.directory / "state.json", state)
        if self.role in {"hub", "ext"}:
            endpoint = self.payload["endpoint"]
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", endpoint):
                raise ValueError("invalid endpoint")
            config = {
                "system": {
                    key: str(self.directory / suffix)
                    for key, suffix in [
                        ("data_dir", "data"),
                        ("generated_dir", "generated"),
                        ("secrets_dir", "secrets"),
                        ("log_dir", "logs"),
                    ]
                },
                "server": {
                    "cn": endpoint,
                    "port": 443,
                    "udp_enabled": False,
                    # The default points at /var/lib/kornode/generated; the case
                    # keeps its own generated_dir, so name the hook explicitly.
                    "connect_script": str(
                        self.directory / "generated" / "ocserv-connect-script-kornode"
                    ),
                    # ext is the "office": its server address is the upstream
                    # health/ping target (10.8.0.1) used by the NL-13 case.
                    **({"ipv4_network": "10.8.0.0/24"} if self.role == "ext" else {}),
                },
                "control": {
                    "enabled": self.role == "hub",
                    "report_interval_seconds": 5,
                    "long_poll_seconds": 5,
                },
                "web": {"enabled": False},
                "egress": [],
            }
            atomic(config_path, config)
        agent = self.role.startswith("agent-")
        service: dict[str, Any] = {
            "image": image,
            "restart": "unless-stopped",
            "init": True,
            "cap_add": ["NET_ADMIN", "NET_RAW"],
            "devices": ["/dev/net/tun:/dev/net/tun"],
            # The reconciler writes these; /proc/sys is read-only in the container.
            "sysctls": {"net.ipv4.ip_forward": 1, "net.ipv4.conf.all.src_valid_mark": 1},
            "volumes": [
                {
                    "type": "bind",
                    "source": str(self.directory),
                    "target": str(self.directory),
                    "read_only": True,
                }
            ],
            "labels": {
                "org.kornode.e2e.run": self.run_id,
                "org.kornode.e2e.role": self.role,
                "org.kornode.e2e.case": self.case,
            },
        }
        if agent:
            if self.role == "agent-a" and self.case == "routed":
                # The access server of agent-a (P4-04, NL-03) and its wg-easy source (NL-05)
                # must be reachable on the VM.
                service["ports"] = [
                    f"{ACCESS_PORT}:{ACCESS_PORT}/tcp",
                    f"{AWG_PORT}:{AWG_PORT}/udp",
                ]
            if self.role == "agent-b" and self.case == "routed":
                service["ports"] = ["9100:9100/tcp"]  # NL-05: the "internet" behind the upstream
            (self.directory / "agent").mkdir(mode=0o700)
            service["volumes"].append(
                {
                    "type": "bind",
                    "source": str(self.directory / "agent"),
                    "target": "/var/lib/kornode-agent",
                }
            )
        else:
            buckets = ["data", "generated", "secrets", "logs", "recovery"]
            for bucket in buckets:
                path = self.directory / bucket
                path.mkdir(mode=0o711 if bucket == "recovery" else 0o700)
                service["volumes"].append(
                    {"type": "bind", "source": str(path), "target": str(path)}
                )
            if config_path.parent != self.directory:
                service["volumes"].append(
                    {
                        "type": "bind",
                        "source": str(config_path.parent),
                        "target": str(config_path.parent),
                    }
                )
            service["environment"] = {"KORNODE_CONFIG": str(config_path)}
            service["ports"] = ["443:443/tcp"] + (["18444:18444/tcp"] if self.role == "hub" else [])
            if self.role in {"hub", "ext"} and self.case == "routed":
                # NL-03: a client of agent-a reaches the hub test listener from outside;
                # E2E-07: ext is the "internet" an exit node reaches.
                service["ports"].append("9100:9100/tcp")
        services = {"node": service}
        compose: dict[str, Any] = {"services": services}
        if self.role in {"agent-b", "hub"} and self.case == "routed":
            # Throwaway VPN client of NL-03 and client behind a source of NL-06 / E2E-07: same
            # image, own network namespace, no kornode.
            source_cidr, node_address, client_address = self.source_network()
            services["client"] = {
                "image": image,
                "init": True,
                "entrypoint": ["sleep", "infinity"],
                "cap_add": ["NET_ADMIN"],
                "devices": ["/dev/net/tun:/dev/net/tun"],
                "labels": service["labels"],
            }
            services["node"]["networks"] = {
                "default": {},
                "source": {"ipv4_address": node_address},
            }
            services["client"]["networks"] = {
                "default": {},
                "source": {"ipv4_address": client_address},
            }
            compose["networks"] = {
                "source": {"ipam": {"config": [{"subnet": source_cidr}]}},
            }
        if self.role == "agent-a" and self.case == "routed":
            (self.directory / "awg").mkdir(mode=0o700)
            services["awg"] = {
                "image": AWG_IMAGE,
                "network_mode": "service:node",
                "cap_add": ["NET_ADMIN"],
                "devices": ["/dev/net/tun:/dev/net/tun"],
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(self.directory / "awg"),
                        "target": "/etc/wireguard",
                    }
                ],
                "environment": {
                    "EXPERIMENTAL_AWG": "true",
                    "OVERRIDE_AUTO_AWG": "awg",
                    "DISABLE_IPV6": "true",
                    "INSECURE": "true",
                    "HOST": "127.0.0.1",
                    "PORT": "51821",
                    "INIT_ENABLED": "true",
                    "INIT_USERNAME": "e2e",
                    "INIT_PASSWORD": secrets.token_hex(12) + "Aa1!",
                    "INIT_HOST": "127.0.0.1",
                    "INIT_PORT": str(AWG_PORT),
                    "INIT_DNS": "9.9.9.9",
                    "INIT_IPV4_CIDR": AWG_SOURCE_CIDR,
                    "INIT_IPV6_CIDR": "fd00:db8::/64",
                    "INIT_ALLOWED_IPS": "0.0.0.0/0",
                },
                "labels": service["labels"],
            }
        if self.role == "agent-b" and self.case == "routed":
            services["awg-client"] = {
                "image": AWG_IMAGE,
                "entrypoint": ["sleep", "infinity"],
                "cap_add": ["NET_ADMIN"],
                "devices": ["/dev/net/tun:/dev/net/tun"],
                "labels": service["labels"],
            }
        atomic(self.directory / "compose.json", compose)
        self.compose("create" if agent else "up", *([] if agent else ["-d"]), "node")
        return {"image_id": identifier}

    def ready(self) -> dict[str, bool]:
        script = 'import socket; s=socket.create_connection(("127.0.0.1",443),2);s.close()'
        if self.role == "hub":
            script += ';s=socket.create_connection(("10.99.0.1",8444),2);s.close()'
        code, _ = self.execute(["python", "-c", script], allowed=(0, 1))
        return {"ready": code == 0}

    def relay(self) -> dict[str, bool]:
        if self.role != "hub":
            raise ValueError("hub only")
        self.run(["docker", "exec", "-d", self.container(), "python", "-c", PROXY])
        return {"started": True}

    def create_agent(self) -> Any:
        if self.role != "hub" or self.payload["name"] not in {"agent-a", "agent-b"}:
            raise ValueError("invalid agent")
        return self.cli("agent", "create", self.payload["name"])

    def enroll(self) -> Any:
        if not self.role.startswith("agent-") or not isinstance(self.payload["token"], str):
            raise ValueError("agent only")
        result = self.compose(
            "run",
            "--rm",
            "-T",
            "--no-deps",
            "--entrypoint",
            "python",
            "node",
            "-c",
            ENROLL,
            data=self.payload["token"].encode(),
            timeout=120,
        )
        self.compose("up", "-d", "node")
        return json.loads(result[1])

    def status(self) -> Any:
        if self.role.startswith("agent-"):
            code, data = self.execute(
                ["kornode-agent", "status", "--json"], allowed=(0, 1, 3, 4), timeout=30
            )
            return {"code": code, "data": json.loads(data)}
        return self.cli("control", "status")

    def probe(self) -> Any:
        if not self.role.startswith("agent-"):
            raise ValueError("agent only")
        gateway = self.payload.get("gateway")
        if gateway and not re.fullmatch(r"[0-9.]+", gateway):
            raise ValueError("invalid gateway")
        code, data = self.execute(
            ["python", "-c", PROBE],
            data=json.dumps({"gateway": gateway}).encode(),
            allowed=(0, 1),
            timeout=10,
        )
        return json.loads(data) if code == 0 else {"status": 0}

    def state(self) -> Any:
        if not self.role.startswith("agent-"):
            raise ValueError("agent only")
        code = (
            "import json;from pathlib import Path;from kornode_agent.store import Store;"
            's=Store(Path("/var/lib/kornode-agent")).load_state();'
            'print(json.dumps({"current":s.current,"high_water":s.high_water,'
            '"last_apply":({"version":s.last_apply.version,"result":s.last_apply.result}'
            "if s.last_apply else None)}))"
        )
        return json.loads(self.execute(["python", "-c", code])[1])

    def identity(self) -> Any:
        return json.loads(self.execute(["python", "-c", IDENTITY])[1])

    def change(self) -> Any:
        if self.role != "hub" or self.payload["name"] not in {"agent-a", "agent-b"}:
            raise ValueError("invalid agent")
        dpd = self.payload.get("dpd", 25)
        if type(dpd) is not int or not 5 <= dpd <= 3600:
            raise ValueError("invalid dpd")
        return self.cli("agent", "set", self.payload["name"], "--dpd", str(dpd))

    def fabric_address(self) -> Any:
        if not self.role.startswith("agent-") or self.case != "routed":
            raise ValueError("routed case, agent only")
        out = self.execute(["ip", "-4", "-j", "addr", "show", "dev", "oc-hub0"])[1]
        return {"address": json.loads(out)[0]["addr_info"][0]["local"]}

    def net_dump(self) -> Any:
        """Routing state of the case container; carries no credentials (addresses,
        rules and routes only), so it may appear in a test failure message."""
        if self.case != "routed":
            raise ValueError("routed case only")
        dump = {}
        for name, argv in (
            ("rules", ["ip", "rule", "show"]),
            ("routes", ["ip", "route", "show", "table", "all"]),
            ("nft", ["nft", "list", "ruleset"]),
            ("rp_filter", ["sysctl", "-a", "--pattern", "rp_filter|ip_forward"]),
            # The test flows only (port 9100): where did the connection get to?
            ("conntrack", ["sh", "-c", "grep 'dport=9100' /proc/net/nf_conntrack | head -8"]),
        ):
            try:
                _, out = self.execute(argv, allowed=tuple(range(256)), timeout=20)
            except (ValueError, subprocess.TimeoutExpired):
                out = b"unavailable"
            dump[name] = out.decode(errors="replace")[:6000]
        return dump

    def resolved_sets(self) -> Any:
        """What the agent's set resolver recorded (addresses only, D-78/D-79)."""
        if not self.role.startswith("agent-") or self.case != "routed":
            raise ValueError("routed case, agent only")
        _, out = self.execute(
            ["sh", "-c", "tail -n +1 /var/lib/kornode-agent/resolved/*.txt 2>&1"],
            allowed=tuple(range(256)),
            timeout=20,
        )
        return {"resolved": out.decode(errors="replace")[:4000]}

    def lan_setup(self) -> Any:
        if not self.role.startswith("agent-") or self.case != "routed":
            raise ValueError("routed case, agent only")
        cidr = str(ipaddress.ip_interface(self.payload["cidr"]))
        for argv in (
            ["ip", "link", "add", "kn-lan0", "type", "dummy"],
            ["ip", "addr", "add", cidr, "dev", "kn-lan0"],
            ["ip", "link", "set", "kn-lan0", "up"],
        ):
            self.execute(argv)
        return {"cidr": cidr}

    def export_prefix(self) -> Any:
        if self.role != "hub" or self.case != "routed":
            raise ValueError("routed case, hub only")
        if self.payload["name"] not in {"agent-a", "agent-b"}:
            raise ValueError("invalid agent")
        cidr = str(ipaddress.ip_network(self.payload["cidr"]))
        return self.cli("agent", "prefix", "add", self.payload["name"], cidr, "--kind", "lan")

    def source_network(self) -> tuple[str, str, str]:
        """CIDR, node and client addresses of the source network of this role."""
        if self.role == "agent-b":
            return SOURCE_CIDR, SOURCE_NODE_ADDRESS, SOURCE_CLIENT_ADDRESS
        if self.role == "hub":
            return HUB_SOURCE_CIDR, HUB_SOURCE_NODE_ADDRESS, HUB_SOURCE_CLIENT_ADDRESS
        raise ValueError("source network: hub and agent-b only")

    def source_iface(self) -> Any:
        """The interface of the node container on the source network (docker names it)."""
        if self.role not in {"agent-b", "hub"} or self.case != "routed":
            raise ValueError("routed case, hub and agent-b only")
        node_address = self.source_network()[1]
        out = self.execute(["ip", "-4", "-j", "addr", "show"])[1]
        for link in json.loads(out):
            if any(a.get("local") == node_address for a in link.get("addr_info", [])):
                return {"interface": link["ifname"]}
        raise ValueError("source network interface not found")

    def source_add(self) -> Any:
        """Declare agent-b's source (hub only); the interface comes from `source_iface`."""
        if self.role != "hub" or self.case != "routed":
            raise ValueError("routed case, hub only")
        interface = self.payload["interface"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            raise ValueError("invalid interface")
        path = self.directory / "source.json"
        atomic(path, {"interface": interface, "cidr": SOURCE_CIDR, "export": True})
        try:
            return self.cli("agent", "source", "add", "agent-b", "e2e-source", "--file", str(path))
        finally:
            path.unlink(missing_ok=True)

    def hub_source_add(self) -> Any:
        """Declare the hub's own source (hub only), exported, standing in for wg-easy."""
        if self.role != "hub" or self.case != "routed":
            raise ValueError("routed case, hub only")
        interface = self.payload["interface"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            raise ValueError("invalid interface")
        path = self.directory / "hub-source.json"
        atomic(path, {"interface": interface, "cidr": HUB_SOURCE_CIDR, "export": True})
        try:
            return self.cli("source", "add", "e2e-hub-source", "--file", str(path))
        finally:
            path.unlink(missing_ok=True)

    def hub_source_policy(self) -> Any:
        """The hub source leaves through agent-b (node 3, role exit) with a full tunnel."""
        if self.role != "hub" or self.case != "routed":
            raise ValueError("routed case, hub only")
        interface = self.payload["interface"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            raise ValueError("invalid interface")
        path = self.directory / "hub-egress.json"
        # `egress set` replaces the whole policy, sources included.
        sources = [
            {"name": "e2e-hub-source", "interface": interface, "cidr": HUB_SOURCE_CIDR,
             "export": True}
        ]  # fmt: skip
        rules = [{"id": "src-out", "from": ["e2e-hub-source"], "to": "any", "via": "exit:3"}]
        atomic(path, {"sources": sources, "egress": rules})
        try:
            return self.cli("egress", "set", "--file", str(path))
        finally:
            path.unlink(missing_ok=True)

    def client_route(self) -> Any:
        """Routes of the client container through the node's source address."""
        if self.role not in {"agent-b", "hub"} or self.case != "routed":
            raise ValueError("routed case, hub and agent-b only")
        node_address = self.source_network()[1]
        self.compose("up", "-d", "client")
        for route in self.payload["routes"]:
            network = str(ipaddress.ip_network(route))
            self.run(
                [
                    "docker", "exec", self.container("client"),
                    "ip", "route", "replace", network, "via", node_address,
                ],
                timeout=20,
            )  # fmt: skip
        return {"routed": True}

    def access_setup(self) -> Any:
        """Role access + listener + one user on a case agent (hub only)."""
        if self.role != "hub" or self.case != "routed" or self.payload["name"] != "agent-a":
            raise ValueError("routed case, hub, agent-a only")
        host = str(ipaddress.ip_address(self.payload["host"]))
        port, user, password = self.payload["port"], self.payload["user"], self.payload["password"]
        if port != ACCESS_PORT:
            raise ValueError("invalid port")
        if not re.fullmatch(r"[a-z][a-z0-9]{1,20}", user) or not isinstance(password, str):
            raise ValueError("invalid user")
        self.cli("agent", "set", "agent-a", "--role", "access")
        self.cli("agent", "access", "set", "agent-a", "--hostname", host, "--port", str(port))
        self.cli(
            "agent", "user", "add", "agent-a", user, "--password-stdin",
            data=password.encode() + b"\n",
        )  # fmt: skip
        return self.cli("agent", "access", "show", "agent-a")

    def access_policy(self) -> Any:
        """Clients of agent-a may use the fabric and leave through the node (fixed policy;
        neither is implied for the clients of an access node)."""
        if self.role != "hub" or self.case != "routed":
            raise ValueError("routed case, hub only")
        path = self.directory / "access-policy.json"
        via = self.payload.get("via", "local")
        if via not in {"local", "exit:3"}:  # exit:3 is agent-b, the second enrolled agent
            raise ValueError("invalid exit")
        domain = self.payload.get("domain")
        to: Any = "any"
        if domain is not None:
            # D-79: only this fabric-zone name leaves through the exit node.
            if via == "local" or not re.fullmatch(r"[a-z0-9-]{1,63}\.kornode\.internal", domain):
                raise ValueError("invalid domain exit")
            to = {"domains": [domain]}
        rules = [
            {"id": "clients-fabric", "from": ["clients"], "to": "fabric", "via": "fabric"},
            {"id": "clients-out", "from": ["clients"], "to": to, "via": via},
        ]
        atomic(path, {"egress": rules})
        try:
            return self.cli("agent", "egress", "set", "agent-a", "--file", str(path))
        finally:
            path.unlink(missing_ok=True)

    def exit_role(self) -> Any:
        """Agent-b becomes an exit node (hub only)."""
        if self.role != "hub" or self.case != "routed":
            raise ValueError("routed case, hub only")
        return self.cli("agent", "set", "agent-b", "--role", "exit")

    def access_client(self) -> Any:
        if self.role != "agent-b" or self.case != "routed":
            raise ValueError("routed case, agent-b only")
        o = self.payload
        options = {
            "host": str(ipaddress.ip_address(o["host"])),
            "port": o["port"],
            "pin": o["pin"],
            "user": o["user"],
            "password": o["password"],
        }
        if not re.fullmatch(r"pin-sha256:[A-Za-z0-9+/=]{44}", options["pin"]):
            raise ValueError("invalid pin")
        options["routes"] = [str(ipaddress.ip_network(route)) for route in o["routes"]]
        options["full"] = o.get("full") is True
        self.compose("up", "-d", "client")
        _, data = self.run(
            ["docker", "exec", "-i", self.container("client"), "python", "-c", ACCESS_CLIENT],
            data=json.dumps(options).encode(),
            timeout=90,
        )
        return json.loads(data)

    def access_diag(self) -> Any:
        """Why a VPN login failed: supervisor state, ocserv/agent log lines and the
        client log. No credentials: ocserv never logs passwords and the client log is
        openconnect's own output."""
        if not self.role.startswith("agent-") or self.case != "routed":
            raise ValueError("routed case, agent only")
        out: dict[str, str] = {}
        if self.role == "agent-a":
            argv = ["supervisorctl", "-c", "/etc/supervisor/conf.d/kornode-agent.conf", "status"]
            out["supervisor"] = self.execute(argv, allowed=tuple(range(256)), timeout=20)[
                1
            ].decode()
            out["listening"] = self.execute(["ss", "-ltnp"], allowed=tuple(range(256)), timeout=20)[
                1
            ].decode()
            out["conf"] = self.execute(
                ["cat", "/run/kornode-access/ocserv.conf"],
                allowed=tuple(range(256)),
                timeout=10,
            )[1].decode()
            _, logs = self.run(
                ["docker", "logs", "--tail", "400", self.container()],
                allowed=tuple(range(256)),
                timeout=30,
            )
            wanted = re.compile(rb"ocserv|access|dnsmasq|resolver", re.I)
            noise = re.compile(rb"spawned:|exited:|entered RUNNING|gave up")
            lines = [
                line for line in logs.splitlines() if wanted.search(line) and not noise.search(line)
            ]
            out["log"] = b"\n".join(lines[:30]).decode(errors="replace")
        else:
            _, log = self.run(
                [
                    "docker", "exec", self.container("client"),
                    "tail", "-n", "25", "/tmp/kn-access/log",
                ],
                allowed=tuple(range(256)),
                timeout=10,
            )  # fmt: skip
            out["client_log"] = log.decode(errors="replace")
            # Whether the tunnel device came up at all, and what is still running there.
            _, state = self.run(
                [
                    "docker", "exec", self.container("client"), "sh", "-c",
                    "ip -4 addr show; ip -4 route show; pgrep -a openconnect",
                ],
                allowed=tuple(range(256)),
                timeout=10,
            )  # fmt: skip
            out["client_state"] = state.decode(errors="replace")[:2500]
        return {key: value[-3000:] for key, value in out.items()}

    def awg_server(self) -> Any:
        """Start the wg-easy source of agent-a (NL-05) and return a client configuration."""
        if self.role != "agent-a" or self.case != "routed":
            raise ValueError("routed case, agent-a only")
        self.compose("up", "-d", "awg", timeout=600)
        container = self.container("awg")
        raw = self.run(["docker", "exec", "-i", container, "node", "-e", AWG_API], timeout=150)[1]
        # The default hooks installed NAT and FORWARD rules in the node's namespace when the
        # interface first came up; kornode owns both for a source, so take them out again.
        for rule in (
            f"-t nat POSTROUTING -s {AWG_SOURCE_CIDR} -o eth0 -j MASQUERADE",
            f"INPUT -p udp -m udp --dport {AWG_PORT} -j ACCEPT",
            "FORWARD -i wg0 -j ACCEPT",
            "FORWARD -o wg0 -j ACCEPT",
        ):
            table, chain = (
                (["-t", "nat"], rule.split()[2:]) if rule.startswith("-t") else ([], rule.split())
            )
            argv = ["iptables", *table, "-D", *chain]
            self.run(["docker", "exec", container, *argv], allowed=(0, 1, 2, 4), timeout=20)
        return json.loads(raw)

    def awg_policy(self) -> Any:
        """The wg-easy source of agent-a leaves through `upstream:office`, kill switch on (hub)."""
        if self.role != "hub" or self.case != "routed":
            raise ValueError("routed case, hub only")
        path = self.directory / "awg-egress.json"
        atomic(
            path,
            {
                "sources": [
                    {"name": "awg", "interface": "wg0", "cidr": AWG_SOURCE_CIDR, "export": True}
                ],
                "egress": [
                    {"id": "awg-out", "from": ["awg"], "to": "any", "via": "upstream:office",
                     "kill_switch": True},
                ],
            },
        )  # fmt: skip
        try:
            return self.cli("agent", "egress", "set", "agent-a", "--file", str(path))
        finally:
            path.unlink(missing_ok=True)

    def awg_client(self) -> Any:
        """Bring up the AmneziaWG client (agent-b VM) from the server's configuration; only the
        listed routes go through the tunnel."""
        if self.role != "agent-b" or self.case != "routed":
            raise ValueError("routed case, agent-b only")
        o = self.payload
        endpoint = f"{ipaddress.ip_address(o['endpoint_host'])}:{AWG_PORT}"
        routes = [str(ipaddress.ip_network(route)) for route in o["routes"]]
        if not isinstance(o["config"], str):
            raise ValueError("invalid config")
        lines: list[str] = []
        for line in o["config"].splitlines():
            key = line.split("=", 1)[0].strip()
            if key in {"DNS", "AllowedIPs", "Endpoint", "PersistentKeepalive"}:
                continue
            if key == "Address":  # IPv6 is switched off
                value = ",".join(
                    v.strip() for v in line.split("=", 1)[1].split(",") if ":" not in v
                )
                line = f"Address = {value}"
            lines.append(line)
            if key == "PublicKey":
                lines += [
                    f"Endpoint = {endpoint}",
                    f"AllowedIPs = {', '.join(routes)}",
                    "PersistentKeepalive = 5",
                ]
        self.compose("up", "-d", "awg-client", timeout=600)
        container = self.container("awg-client")
        self.run(
            ["docker", "exec", container, "awg-quick", "down", "/tmp/awg0.conf"], allowed=(0, 1)
        )
        self.run(
            ["docker", "exec", "-i", container, "sh", "-c", "cat > /tmp/awg0.conf"],
            data=("\n".join(lines) + "\n").encode(),
        )
        self.run(["docker", "exec", container, "awg-quick", "up", "/tmp/awg0.conf"], timeout=60)
        return {"up": True}

    def awg_client_stop(self) -> Any:
        if self.role != "agent-b" or self.case != "routed":
            raise ValueError("routed case, agent-b only")
        self.compose("stop", "awg-client")
        return {"stopped": True}

    def access_client_stop(self) -> Any:
        if self.role != "agent-b" or self.case != "routed":
            raise ValueError("routed case, agent-b only")
        self.compose("stop", "client")
        return {"stopped": True}

    def dns_record(self) -> Any:
        if self.role != "hub" or self.case != "routed":
            raise ValueError("routed case, hub only")
        name, kind = self.payload["name"], self.payload["type"]
        if not re.fullmatch(r"[a-z0-9-]{1,63}", name) or kind not in {"A", "AAAA", "CNAME"}:
            raise ValueError("invalid record")
        value = str(ipaddress.ip_address(self.payload["value"]))
        return self.cli("dns", "record", "add", name, kind, value)

    def dns_resolve(self) -> Any:
        if not (self.role == "hub" or self.role.startswith("agent-")) or self.case != "routed":
            raise ValueError("routed case only")
        name = self.payload["name"]
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", name):
            raise ValueError("invalid name")
        server = str(ipaddress.ip_address(self.payload["server"]))
        _, data = self.execute(
            ["python", "-c", RESOLVE],
            data=json.dumps({"name": name, "server": server}).encode(),
            timeout=20,
        )
        return json.loads(data)

    def fabric_listen(self) -> Any:
        if self.role not in {"hub", "ext"} and not self.role.startswith("agent-"):
            raise ValueError("routed case only")
        if self.case != "routed":
            raise ValueError("routed case only")
        seconds = self.payload["seconds"]
        if type(seconds) is not int or not 1 <= seconds <= 120:
            raise ValueError("invalid window")
        data = json.dumps({"port": 9100, "seconds": seconds}).encode()
        if self.payload.get("client"):
            if self.role not in {"agent-b", "hub"}:
                raise ValueError("the client container belongs to agent-b or the hub")
            argv = ["docker", "exec", "-i", self.container("client"), "python", "-c", LISTEN]
            return json.loads(self.run(argv, data=data, timeout=seconds + 20)[1])
        return json.loads(
            self.execute(["python", "-c", LISTEN], data=data, timeout=seconds + 20)[1]
        )

    def fabric_connect(self) -> Any:
        if self.case != "routed":
            raise ValueError("routed case only")
        host = str(ipaddress.ip_address(self.payload["host"]))
        source = self.payload.get("source")
        if source is not None:
            source = str(ipaddress.ip_address(source))
        data = json.dumps({"host": host, "port": 9100, "source": source}).encode()
        if self.payload.get("awg"):
            if self.role != "agent-b":
                raise ValueError("the AmneziaWG client runs on agent-b")
            argv = ["docker", "exec", "-i", self.container("awg-client"), "node", "-e", AWG_CONNECT]
            return json.loads(self.run(argv, data=data, timeout=20)[1])
        if self.payload.get("client"):
            if self.role not in {"agent-b", "hub"}:
                raise ValueError("the client container runs on agent-b or the hub")
            argv = ["docker", "exec", "-i", self.container("client"), "python", "-c", CONNECT]
            return json.loads(self.run(argv, data=data, timeout=20)[1])
        return json.loads(self.execute(["python", "-c", CONNECT], data=data, timeout=20)[1])

    def repair_route(self) -> Any:
        if not self.role.startswith("agent-") or self.case != "route":
            raise ValueError("route case only")
        return json.loads(self.execute(["python", "-c", REPAIR_ROUTE])[1])

    def inject_bundle(self) -> Any:
        if self.role != "hub" or self.case not in {"rollback", "tamper"}:
            raise ValueError("bundle fault case only")
        return json.loads(
            self.execute(
                ["python", "-c", INJECT_BUNDLE],
                data=json.dumps({"tamper": self.case == "tamper"}).encode(),
            )[1]
        )

    def rejected(self) -> Any:
        if not self.role.startswith("agent-") or self.case != "tamper":
            raise ValueError("tamper case only")

        # Docker writes application stderr to its own stderr. Capture both streams
        # privately below; never return logs or add raw Docker logs to artifacts.
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(
                [
                    "docker",
                    "--host",
                    "unix:///var/run/docker.sock",
                    "logs",
                    "--tail",
                    "200",
                    self.container(),
                ],
                stdout=output,
                stderr=output,
                timeout=10,
                check=False,
            )
            if result.returncode:
                raise ValueError("log evidence unavailable")
            output.seek(0)
            raw = output.read(1024 * 1024)
        return {"rejected": b"invalid_bundle bad_signature" in raw}

    def rollback_report(self) -> Any:
        if self.role != "hub" or self.case != "rollback":
            raise ValueError("rollback case only")
        version = self.payload["version"]
        if type(version) is not int or not 1 <= version <= 2**31 - 1:
            raise ValueError("invalid version")
        reports = self.cli("agent", "status", "agent-a", "--limit", "20")["reports"]
        return {
            "reported": any(
                row["body"].get("last_apply", {}).get("version") == version
                and row["body"].get("last_apply", {}).get("result") == "rolled_back"
                for row in reports
                if row["body"].get("last_apply")
            )
        }

    def revoke(self) -> Any:
        if self.role != "hub":
            raise ValueError("hub only")
        return self.cli("agent", "revoke", "agent-b", "--yes")

    def fault(self) -> Any:
        if not self.role.startswith("agent-"):
            raise ValueError("agent only")
        container = self.container()
        # Watchdog is armed before insertion, independent of SSH/pytest lifetime.
        subprocess.Popen(
            [sys.executable, "-c", WATCHDOG, container],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        rules = (
            b"table inet kn_e2e_fault { chain output { type filter hook output priority -300; "
            b'policy accept; oifname "lo" accept; counter drop; }; }\n'
        )
        self.execute(["nft", "-f", "-"], data=rules)
        return {"seconds": 60}

    def ext_user(self) -> Any:
        if self.role != "ext" or not isinstance(self.payload["password"], str):
            raise ValueError("ext only")
        self.execute(["python", "-c", EXT_USER], data=json.dumps(self.payload).encode())
        return self.cli("certificates", "pin", json_flag=False)

    def upstream_ping(self) -> Any:
        if self.role != "agent-a" or self.case != "cache":
            raise ValueError("cache case only")
        code, _ = self.execute(
            ["ping", "-c", "1", "-W", "2", "-I", "oc-office", "10.8.0.1"],
            allowed=(0, 1, 2),
            timeout=5,
        )
        return {"reachable": code == 0}

    def upstream(self) -> Any:
        if self.role != "hub":
            raise ValueError("hub only")
        path = self.directory / "upstream.json"
        atomic(path, self.payload["spec"])
        try:
            return self.cli("agent", "upstream", "set", "agent-a", "office", "--file", str(path))
        finally:
            path.unlink(missing_ok=True)

    def rotate(self) -> Any:
        if self.role != "hub":
            raise ValueError("hub only")
        return self.cli("control", "rotate-signing-key", "--yes")

    def stop(self) -> Any:
        self.owned_case()
        self.compose("stop", "node")
        return {"stopped": True}

    def restart(self) -> Any:
        state = self.owned_case()
        image = self.payload.get("image", state["image"])
        image_id = self.image(image)
        compose = json.loads((self.directory / "compose.json").read_text())
        compose["services"]["node"]["image"] = image
        atomic(self.directory / "compose.json", compose)
        state["image"] = image
        atomic(self.directory / "state.json", state)
        self.compose("up", "-d", "--force-recreate", "node")
        if self.role == "hub":
            self.relay()
        return {"image_id": image_id}

    def backup(self) -> Any:
        if self.role != "hub":
            raise ValueError("hub only")
        # Generated on the VM; passphrase/key/archive are never returned or artifacts.
        import secrets

        path = self.directory / "recovery" / "passphrase"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(secrets.token_urlsafe(48))
            handle.flush()
            os.fsync(handle.fileno())
        return self.cli(
            "hub",
            "backup",
            "--out",
            str(self.directory / "recovery" / "hub.knbackup"),
            "--passphrase-file",
            str(path),
        )

    def restore(self) -> Any:
        if self.role != "hub":
            raise ValueError("hub only")
        state = self.owned_case()
        self.compose("stop", "node")
        # ONLY the case's known bind-mounted data subtree, after stopping its hub.
        data = self.directory / "data"
        if data.is_symlink() or data.parent != self.directory:
            raise ValueError("unsafe wipe")
        shutil.rmtree(data)
        data.mkdir(mode=0o700)
        result = self.compose(
            "run",
            "--rm",
            "-T",
            "--no-deps",
            "--entrypoint",
            "korctl",
            "node",
            "--config",
            state["config"],
            "hub",
            "restore",
            str(self.directory / "recovery" / "hub.knbackup"),
            "--target",
            str(self.directory / "recovery" / "restored"),
            "--passphrase-file",
            str(self.directory / "recovery" / "passphrase"),
            "--yes",
            "--json",
            timeout=300,
        )
        restored = json.loads(result[1])
        expected = self.directory / "recovery" / "restored" / "config.yaml"
        if (
            restored["config_path"] != str(expected)
            or expected.parent.is_symlink()
            or expected.is_symlink()
            or not expected.is_file()
            or not expected.resolve().is_relative_to((self.directory / "recovery").resolve())
        ):
            raise ValueError("unexpected restore path")
        expected.parent.chmod(0o711)  # explicit activation for dropped-privilege workers
        state["config"] = str(expected)
        compose = json.loads((self.directory / "compose.json").read_text())
        compose["services"]["node"]["environment"]["KORNODE_CONFIG"] = str(expected)
        atomic(self.directory / "compose.json", compose)
        atomic(self.directory / "state.json", state)
        self.compose("up", "-d", "--force-recreate", "node")
        self.relay()
        return {"staged_and_activated": True}

    def diagnostics(self) -> Any:
        if not self.role.startswith("agent-"):
            return {"available": False}
        path = self.directory / "agent" / "diagnostic.tar.gz"
        if path.exists():
            path.unlink()
        self.execute(
            ["kornode-agent", "diag", "--out", "/var/lib/kornode-agent/diagnostic.tar.gz", "--json"]
        )
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 5 * 1024 * 1024:
                raise ValueError("unsafe diagnostics")
            data = handle.read(5 * 1024 * 1024 + 1)
        if len(data) > 5 * 1024 * 1024:
            raise ValueError("unsafe diagnostics")
        return {"available": True, "archive": base64.b64encode(data).decode()}

    def cleanup(self) -> Any:
        if not self.directory.exists():
            return {"clean": True}
        self.owned_case()
        if (self.directory / "compose.json").is_file():
            self.compose("down", "--volumes", "--remove-orphans", timeout=120)
        shutil.rmtree(self.directory)
        return {"clean": True}

    def release(self) -> Any:
        if list(self.root.iterdir()):
            raise ValueError("case cleanup incomplete; lease retained")
        for kind in ("hub", "agent"):
            tag = f"kornode-e2e:{kind}-{self.run_id}"
            present, _ = self.run(["docker", "image", "inspect", tag], allowed=(0, 1))
            if present == 0:
                self.run(["docker", "image", "rm", tag])
        self.root.rmdir()
        (self.base / "lease.json").unlink()
        return {"released": True}

    def pull_previous(self) -> Any:
        for field in ("hub", "agent"):
            image = self.payload[field]
            if not IMAGE_RE.fullmatch(image) or "@sha256:" not in image:
                raise ValueError("immutable baseline required")
            self.run(["docker", "pull", image], timeout=300)
        return {"hub": self.image(self.payload["hub"]), "agent": self.image(self.payload["agent"])}

    def recover(self) -> Any:
        self.guard(lease=False)
        lease = self.base / "lease.json"
        if not lease.exists() and not self.root.exists():
            return {"released": True}
        self.guard()
        try:
            for case in sorted(CASES):
                self.case, self.directory = case, self.root / case
                if self.directory.exists():
                    self.cleanup()
        finally:
            self.case, self.directory = "", self.root
        return self.release()

    def dispatch(self, stream: BinaryIO) -> Any:
        action = self.request["action"]
        if action == "preflight":
            return self.preflight()
        if action == "claim":
            return self.claim()
        if action == "recover":
            return self.recover()
        self.guard()
        if action == "load_images":
            return self.load_images(stream)
        permitted = {
            "deploy",
            "ready",
            "relay",
            "create_agent",
            "enroll",
            "status",
            "probe",
            "identity",
            "state",
            "change",
            "revoke",
            "repair_route",
            "fabric_address",
            "lan_setup",
            "net_dump",
            "resolved_sets",
            "export_prefix",
            "dns_record",
            "dns_resolve",
            "source_iface",
            "source_add",
            "hub_source_add",
            "hub_source_policy",
            "client_route",
            "exit_role",
            "access_setup",
            "access_policy",
            "access_client",
            "access_diag",
            "access_client_stop",
            "awg_server",
            "awg_policy",
            "awg_client",
            "awg_client_stop",
            "fabric_listen",
            "fabric_connect",
            "inject_bundle",
            "rejected",
            "rollback_report",
            "fault",
            "ext_user",
            "upstream",
            "upstream_ping",
            "rotate",
            "stop",
            "restart",
            "backup",
            "restore",
            "diagnostics",
            "cleanup",
            "release",
            "pull_previous",
        }
        if action not in permitted:
            raise ValueError("unknown action")
        return getattr(self, action)()


def main() -> int:
    try:
        header = sys.stdin.buffer.readline(65537)
        if len(header) > 65536 or not header.endswith(b"\n"):
            raise ValueError("request too large")
        worker = Worker(json.loads(header))
        result = worker.dispatch(sys.stdin.buffer)
        print(json.dumps({"ok": True, "result": result}))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "remote_action_failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
