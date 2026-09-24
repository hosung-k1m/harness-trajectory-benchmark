package gvisor

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

const fakeSudo = `#!/bin/sh
set -u
if [ "${1:-}" = "-n" ]; then shift; fi
state="${FAKE_DOCKER_STATE:?FAKE_DOCKER_STATE required}"
printf '%s\n' "$*" >> "${state}/argv.log"
if [ "$#" -eq 0 ]; then exit 0; fi
cmd="$1"; shift
case "${cmd}" in
  install)
    dir=""
    for a in "$@"; do dir="$a"; done
    mkdir -p "${dir}"
    ;;
  rm)
    exec rm "$@"
    ;;
  tar)
    if [ -f "${state}/fail-tar" ]; then echo "tar denied" >&2; exit 1; fi
    exec tar "$@"
    ;;
  ls|cp)
    first=1
    for a in "$@"; do
      case "$a" in
        /var/log/benchmark-gvisor|/var/log/benchmark-gvisor/*)
          if [ -n "${FAKE_RUNSC_DIR:-}" ]; then a="${FAKE_RUNSC_DIR}${a#/var/log/benchmark-gvisor}"; fi
          ;;
        /run/benchmark-gvisor/seccheck|/run/benchmark-gvisor/seccheck/*)
          if [ -n "${FAKE_SECCHECK_DIR:-}" ]; then a="${FAKE_SECCHECK_DIR}${a#/run/benchmark-gvisor/seccheck}"; fi
          ;;
      esac
      if [ "${first}" = 1 ]; then set -- "$a"; first=0; else set -- "$@" "$a"; fi
    done
    exec "${cmd}" "$@"
    ;;
  docker)
    sub="$1"; shift
    case "${sub}" in
      exec)
        if [ -f "${state}/gateway-probe-fails" ]; then echo "listener unavailable" >&2; exit 1; fi
        exit 0
        ;;
      network)
        action="$1"; shift
        case "${action}" in
          create)
            if [ -f "${state}/fail-network-create" ]; then echo "network create denied" >&2; exit 1; fi
            name=""
            for a in "$@"; do
              case "$a" in
                com.docker.network.bridge.name=*) printf '%s' "${a#*=}" > "${state}/bridge-name" ;;
                -*) ;;
                *) name="$a" ;;
              esac
            done
            touch "${state}/network-${name}"; echo "${name}"
            ;;
          inspect)
            if [ -f "${state}/network-$1" ]; then printf '[{"Name":"%s","Driver":"bridge"}]\n' "$1"; else echo "network $1 not found" >&2; exit 1; fi
            ;;
          rm)
            if [ -f "${state}/fail-network-rm" ]; then echo "network rm denied" >&2; exit 1; fi
            if [ -f "${state}/network-$1" ]; then rm -f "${state}/network-$1"; else echo "network $1 not found" >&2; exit 1; fi
            ;;
        esac
        ;;
      run)
        gw=0
        for a in "$@"; do case "$a" in mitmdump) gw=1;; esac; done
        if [ "$gw" = 1 ]; then
          render=0; name=""; mdir=""; netname=""
          for a in "$@"; do
            case "$a" in
              -nr) render=1;;
              --name=*) name="${a#--name=}";;
              --network=*) netname="${a#--network=}";;
              --mount=*) m="${a#--mount=}"
                case "$m" in *"dst=/home/mitmproxy/.mitmproxy"*) mdir="${m#*src=}"; mdir="${mdir%%,*}";; esac;;
            esac
          done
          if [ "$render" = 1 ]; then
            if [ -f "${state}/fail-gateway-render" ]; then echo "render failed" >&2; exit 1; fi
            case "$*" in
              *dumper_filter*)
                if [ ! -f "${state}/empty-gateway-dns" ]; then printf '172.18.0.3:42152: DNS QUERY (A) probe.invalid\n << NXDOMAIN\n'; fi
                ;;
              *) printf '172.18.0.3:23427: GET http://mitm.it/\n               << 200 OK 17.5k\n';;
            esac
            exit 0
          fi
          if [ -z "$name" ]; then echo "missing gateway --name" >&2; exit 1; fi
          if [ -f "${state}/fail-gateway" ]; then echo "gateway start denied" >&2; exit 1; fi
          printf '%s\n' "$@" > "${state}/runargs-${name}"
          touch "${state}/container-${name}"
          if [ -n "$netname" ]; then printf '%s' "$netname" > "${state}/net-${name}"; fi
          printf 'mitmdump listening\n' > "${state}/logs-out-${name}"
          if [ -n "$mdir" ] && [ -d "$mdir" ]; then
            if [ ! -f "${state}/gateway-noca" ]; then printf 'CA CERT\n' > "${mdir}/mitmproxy-ca-cert.pem"; fi
            printf 'PRIVATE KEY\n' > "${mdir}/mitmproxy-ca.pem"
            printf 'FLOWDATA\n' > "${mdir}/flows.mitm"
          fi
          echo "gw-${name}"
          exit 0
        fi
        name=""
        for a in "$@"; do case "$a" in --name=*) name="${a#--name=}";; esac; done
        if [ -z "${name}" ]; then echo "missing --name" >&2; exit 1; fi
        printf '%s\n' "$@" > "${state}/runargs-${name}"
        touch "${state}/container-${name}"
        if [ -f "${state}/fail-run" ]; then echo "daemon start failure" >&2; exit 1; fi
        if [ -f "${state}/bad-id" ]; then echo "unexpected-id"; exit 0; fi
        n=0
        if [ -f "${state}/id-seq" ]; then n="$(cat "${state}/id-seq")"; fi
        n=$((n + 1)); printf '%s' "${n}" > "${state}/id-seq"
        id="$(printf 'facefeed%056x' "${n}")"
        printf '%s\n' "${id}" > "${state}/id-${name}"
        printf 'stdout-from-%s\n' "${name}" > "${state}/logs-out-${name}"
        printf 'stderr-from-%s\n' "${name}" > "${state}/logs-err-${name}"
        if [ -n "${FAKE_RUNSC_DIR:-}" ] && [ -d "${FAKE_RUNSC_DIR}" ]; then
          printf 'boot log %s\n' "${id}" > "${FAKE_RUNSC_DIR}/runsc.${id}.boot.log"
          printf 'gofer log %s\n' "${id}" > "${FAKE_RUNSC_DIR}/runsc.${id}.gofer.log"
          printf 'not a log\n' > "${FAKE_RUNSC_DIR}/runsc.${id}.notes.txt"
        fi
        if [ -n "${FAKE_SECCHECK_DIR:-}" ] && [ -d "${FAKE_SECCHECK_DIR}" ]; then
          if [ -f "${state}/seccheck-frames" ]; then
            cp "${state}/seccheck-frames" "${FAKE_SECCHECK_DIR}/${id}.frames"
          else
            printf '\000\000\000\004ABCD\000\000\000\003XYZ' > "${FAKE_SECCHECK_DIR}/${id}.frames"
          fi
          if [ -f "${state}/seccheck-status" ]; then
            cp "${state}/seccheck-status" "${FAKE_SECCHECK_DIR}/${id}.done"
          else
            printf '%s\n' '{"frames":2,"oversize":0,"reportedDrops":0}' > "${FAKE_SECCHECK_DIR}/${id}.done"
          fi
        fi
        echo "${id}"
        if [ -f "${state}/autoexit" ]; then cp "${state}/autoexit" "${state}/exit-${name}"; fi
        ;;
      inspect)
        c=""; fmt=""; prev=""
        for a in "$@"; do
          if [ "${prev}" = "--format" ]; then fmt="$a"; fi
          prev="$a"; c="$a"
        done
        if [ -f "${state}/gone-${c}" ]; then echo "No such container: ${c}" >&2; exit 1; fi
        case "$fmt" in
          *NetworkSettings*)
            net=""
            if [ -f "${state}/net-${c}" ]; then net="$(cat "${state}/net-${c}")"; fi
            if [ -f "${state}/gateway-badip" ]; then
              printf '{"%s":{"IPAddress":"not-an-ip"}}\n' "${net}"
            else
              printf '{"%s":{"IPAddress":"10.88.0.2"}}\n' "${net}"
            fi
            ;;
          *Running*)
            if [ -f "${state}/gateway-exited" ]; then echo "false"; else echo "true"; fi
            ;;
          *)
            if [ -f "${state}/no-pid" ]; then echo "0"; exit 0; fi
            n=0
            if [ -f "${state}/inspect-n-${c}" ]; then n="$(cat "${state}/inspect-n-${c}")"; fi
            n=$((n + 1)); printf '%s' "${n}" > "${state}/inspect-n-${c}"
            if [ "${n}" -eq 1 ]; then echo "4242"; else echo "0"; fi
            ;;
        esac
        ;;
      logs)
        c="$1"
        if [ -f "${state}/fail-logs" ]; then echo "logs unavailable" >&2; exit 1; fi
        cat "${state}/logs-out-${c}" 2>/dev/null || true
        cat "${state}/logs-err-${c}" >&2 2>/dev/null || true
        ;;
      stats)
        c=""
        for a in "$@"; do c="$a"; done
        if [ -f "${state}/fail-stats" ] || [ -f "${state}/gone-${c}" ]; then echo "stats unavailable" >&2; exit 1; fi
        s=0
        if [ -f "${state}/stats-seq" ]; then s="$(cat "${state}/stats-seq")"; fi
        s=$((s + 1)); printf '%s' "${s}" > "${state}/stats-seq"
        printf 'CONTAINER %s CPU=1.0 MEM=2.0 SAMPLE=%s\n' "${c}" "${s}"
        ;;
      wait)
        c="$1"
        if [ -f "${state}/wait-fails" ]; then echo "daemon unavailable" >&2; exit 1; fi
        if [ -f "${state}/wait-garbage" ]; then echo "not-an-exit-code"; exit 0; fi
        n=0
        while [ ! -f "${state}/exit-${c}" ]; do
          if [ -f "${state}/gone-${c}" ]; then echo "No such container: ${c}" >&2; exit 1; fi
          n=$((n + 1))
          if [ "${n}" -gt 600 ]; then echo "wait timeout" >&2; exit 1; fi
          sleep 0.02
        done
        cat "${state}/exit-${c}"
        ;;
      kill)
        c="$1"
        if [ -f "${state}/gone-${c}" ]; then echo "No such container: ${c}" >&2; exit 1; fi
        if [ -f "${state}/exit-${c}" ]; then echo "container ${c} is not running" >&2; exit 1; fi
        echo "137" > "${state}/exit-${c}"
        ;;
      stop)
        c=""
        for a in "$@"; do case "$a" in --*) ;; *) c="$a";; esac; done
        if [ -f "${state}/fail-gateway-stop" ]; then echo "stop denied" >&2; exit 1; fi
        touch "${state}/stopped-${c}"
        echo "${c}"
        ;;
      rm)
        if [ -f "${state}/fail-rm" ]; then echo "container rm denied" >&2; exit 1; fi
        c=""
        for a in "$@"; do case "$a" in --*) ;; *) c="$a";; esac; done
        if [ -f "${state}/container-${c}" ]; then
          rm -f "${state}/container-${c}" "${state}/runargs-${c}"
          touch "${state}/gone-${c}"
        else
          echo "No such container: ${c}" >&2; exit 1
        fi
        ;;
      *)
        echo "unhandled docker subcommand ${sub}" >&2; exit 1
        ;;
    esac
    ;;
  nsenter)
    if [ -f "${state}/fail-nsenter" ]; then echo "nsenter denied" >&2; exit 1; fi
    pid=""
    prev=""
    for a in "$@"; do
      if [ "${prev}" = "-t" ]; then pid="$a"; fi
      prev="$a"
    done
    if [ -z "${pid}" ] || [ "${pid}" = "0" ]; then echo "nsenter: invalid pid" >&2; exit 1; fi
    case "$*" in
      *"link show dev eth0"*)
        idx=17
        if [ -f "${state}/veth-index" ]; then idx="$(cat "${state}/veth-index")"; fi
        printf '[{"ifindex":2,"ifname":"eth0","link_index":%s,"link_type":"ether"}]\n' "${idx}"
        ;;
      *"ip -j addr"*)
        printf '[{"ifindex":2,"ifname":"eth0","addr_info":[{"local":"10.44.0.2","prefixlen":24,"scope":"global"}]}]\n'
        ;;
      *"ip -j route"*)
        printf '[{"dst":"default","gateway":"10.44.0.1","dev":"eth0"}]\n'
        ;;
      *)
        echo "unhandled nsenter $*" >&2; exit 1
        ;;
    esac
    ;;
  ip)
    if [ -f "${state}/fail-ip" ]; then echo "ip denied" >&2; exit 1; fi
    case "$*" in
      "-j link show")
        br=""
        if [ -f "${state}/bridge-name" ]; then br="$(cat "${state}/bridge-name")"; fi
        idx=17
        if [ -f "${state}/veth-index" ]; then idx="$(cat "${state}/veth-index")"; fi
        ifname="veth7f3a99"
        if [ -f "${state}/veth-badname" ]; then ifname="eth9"; fi
        master="${br}"
        if [ -f "${state}/veth-wrongmaster" ]; then master="br-other"; fi
        printf '[{"ifindex":1,"ifname":"lo","link_type":"loopback"}'
        if [ ! -f "${state}/veth-missing" ]; then
          printf ',{"ifindex":%s,"ifname":"%s","master":"%s","link_type":"ether"}' "${idx}" "${ifname}" "${master}"
          if [ -f "${state}/veth-dup" ]; then
            printf ',{"ifindex":%s,"ifname":"%s-dup","master":"%s","link_type":"ether"}' "${idx}" "${ifname}" "${master}"
          fi
        fi
        printf ']\n'
        ;;
      "-j addr show dev "*)
        dev="${*##* }"
        printf '[{"ifindex":3,"ifname":"%s","addr_info":[{"local":"10.44.0.1","prefixlen":24,"scope":"global"}]}]\n' "${dev}"
        ;;
      "-j route")
        printf '[{"dst":"default","gateway":"10.44.0.254","dev":"eth0"}]\n'
        ;;
      "-s link show dev "*)
        dev="${*##* }"
        printf '3: %s: <BROADCAST,MULTICAST> mtu 1500 state UP\n    RX: 100 packets 8000 bytes\n' "${dev}"
        ;;
      *)
        echo "unhandled ip $*" >&2; exit 1
        ;;
    esac
    ;;
  chown)
    exit 0
    ;;
  iptables-save)
    if [ -f "${state}/fail-iptables" ]; then echo "iptables-save denied" >&2; exit 1; fi
    printf '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n'
    ;;
  nft)
    if [ -f "${state}/fail-nft" ]; then echo "nft denied" >&2; exit 1; fi
    printf 'table ip filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n\t}\n}\n'
    ;;
  tcpdump)
    if [ -f "${state}/fail-tcpdump" ]; then echo "tcpdump denied" >&2; exit 1; fi
    w=""; iface=""; q=""
    prev=""
    for a in "$@"; do
      case "${prev}" in
        -w) w="$a" ;;
        -i) iface="$a" ;;
        -Q) q="$a" ;;
      esac
      prev="$a"
    done
    if [ -z "${w}" ]; then echo "tcpdump: missing -w" >&2; exit 1; fi
    printf 'PCAP:%s:%s\n' "${iface}" "${q}" > "${w}"
    if [ -f "${state}/tcpdump-hang" ]; then
      ( trap '' INT TERM; while :; do date +%s%N > "${state}/hang-heartbeat"; sleep 0.1; done ) &
      trap '' INT
      while :; do sleep 0.05; done
    fi
    if [ -f "${state}/tcpdump-slow-listen" ]; then sleep 0.3; fi
    if [ ! -f "${state}/tcpdump-nolisten" ]; then
      printf 'tcpdump: listening on %s, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n' "${iface}" >&2
    fi
    if [ -f "${state}/tcpdump-nostats" ]; then
      trap 'exit 0' INT
    else
      kd=0
      if [ -f "${state}/tcpdump-drops" ]; then kd="$(cat "${state}/tcpdump-drops")"; fi
      trap 'printf "3 packets captured\n3 packets received by filter\n%s packets dropped by kernel\n" "${kd}" >&2; exit 0' INT
    fi
    while :; do sleep 0.05; done
    ;;
  *)
    echo "unhandled command ${cmd}" >&2; exit 1
    ;;
esac
`

func installFakeSudo(t *testing.T) string {
	t.Helper()
	state := t.TempDir()
	bin := filepath.Join(t.TempDir(), "sudo")
	if err := os.WriteFile(bin, []byte(fakeSudo), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DOCKER_STATE", state)
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	return state
}

func argvLog(t *testing.T, state string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(state, "argv.log"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimRight(string(b), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func dockerCalls(t *testing.T, state string) []string {
	t.Helper()
	var out []string
	for _, line := range argvLog(t, state) {
		if strings.HasPrefix(line, "docker ") {
			out = append(out, line)
		}
	}
	return out
}

func onlyContainer(t *testing.T, state string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(state, "runargs-*"))
	var kept []string
	for _, m := range matches {
		if strings.HasPrefix(filepath.Base(m), "runargs-htb-gateway-") {
			continue
		}
		kept = append(kept, m)
	}
	if err != nil || len(kept) != 1 {
		t.Fatalf("runargs files = %v, %v", matches, err)
	}
	return strings.TrimPrefix(filepath.Base(kept[0]), "runargs-")
}

func onlyNetwork(t *testing.T, state string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(state, "network-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("network markers = %v, %v", matches, err)
	}
	return strings.TrimPrefix(filepath.Base(matches[0]), "network-")
}

func runArgs(t *testing.T, state, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(state, "runargs-"+name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func testSpec(id string) backend.RunSpec {
	d := backend.SHA256Hex([]byte(id))
	return backend.RunSpec{SchemaVersion: "v1", RunID: id, HarnessDigest: d, BenchmarkDigest: d, PolicyDigest: d}
}

func testPlan(t *testing.T, image string, command ...string) backend.ObservationPlan {
	t.Helper()
	raw, err := json.Marshal(containerConfig{Type: "gvisor/container-v1", Image: image, Command: command})
	if err != nil {
		t.Fatal(err)
	}
	return planWithConfigs(raw)
}

func planWithConfigs(configs ...json.RawMessage) backend.ObservationPlan {
	return backend.ObservationPlan{SchemaVersion: "v1", OpaqueTrafficPolicy: backend.OpaqueTrafficAllow, SensorConfigs: configs}
}

func TestPrepareRejectsInvalidSensorConfig(t *testing.T) {
	state := installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	valid := `{"type":"gvisor/container-v1","image":"alpine:3.21","command":["sh","-c","true"]}`
	cases := []struct {
		name string
		plan backend.ObservationPlan
	}{
		{"no-config", planWithConfigs()},
		{"two-configs", planWithConfigs(json.RawMessage(valid), json.RawMessage(valid))},
		{"trailing-json", planWithConfigs(json.RawMessage(valid + ` {}`))},
		{"not-an-object", planWithConfigs(json.RawMessage(`"gvisor/container-v1"`))},
		{"wrong-type", planWithConfigs(json.RawMessage(`{"type":"other/v1","image":"alpine:3.21","command":["sh"]}`))},
		{"missing-type", planWithConfigs(json.RawMessage(`{"image":"alpine:3.21","command":["sh"]}`))},
		{"unknown-field", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"alpine:3.21","command":["sh"],"extra":1}`))},
		{"env-rejected", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"alpine:3.21","command":["sh"],"env":{"A":"B"}}`))},
		{"empty-image", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"","command":["sh"]}`))},
		{"missing-image", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","command":["sh"]}`))},
		{"flag-like-image", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"--privileged","command":["sh"]}`))},
		{"space-in-image", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"alpine:3.21 next","command":["sh"]}`))},
		{"empty-command", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"alpine:3.21","command":[]}`))},
		{"missing-command", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"alpine:3.21"}`))},
		{"empty-arg", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"alpine:3.21","command":["sh",""]}`))},
		{"blank-program", planWithConfigs(json.RawMessage(`{"type":"gvisor/container-v1","image":"alpine:3.21","command":["  "]}`))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := b.Prepare(context.Background(), testSpec("run-config"), tc.plan); err == nil {
				t.Fatal("Prepare succeeded")
			}
		})
	}
	if calls := dockerCalls(t, state); len(calls) != 0 {
		t.Fatalf("rejected plans still invoked docker: %v", calls)
	}
}

func TestPrepareRejectsVerifiedAndUnsupportedRequirements(t *testing.T) {
	installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	verified := testSpec("run-verified")
	verified.Verified = true
	if _, err := b.Prepare(context.Background(), verified, testPlan(t, "alpine:3.21", "true")); err == nil {
		t.Fatal("verified run was accepted")
	}
	plan := testPlan(t, "alpine:3.21", "true")
	plan.Requirements = []backend.ObservationRequirement{{EventFamily: "network/plaintext", MinimumObservation: backend.ObservationComplete, MinimumEnforcement: backend.EnforcementSynchronous, Retention: "raw"}}
	if _, err := b.Prepare(context.Background(), testSpec("run-plaintext"), plan); err == nil {
		t.Fatal("plan requiring complete plaintext capture was accepted")
	}
}

func TestPrepareRejectsUnusableRunID(t *testing.T) {
	installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	plan := testPlan(t, "alpine:3.21", "true")
	for _, id := range []string{"", "a/b", "..", "-x", ".x", "a b", "a;b", "a:b", strings.Repeat("a", 200)} {
		if _, err := b.Prepare(context.Background(), testSpec(id), plan); err == nil {
			t.Fatalf("run ID %q was accepted", id)
		}
	}
	if _, err := b.Prepare(context.Background(), testSpec("run-ok_1.2"), plan); err != nil {
		t.Fatalf("valid run ID rejected: %v", err)
	}
}

func TestPrepareAllocatesWithoutDockerSideEffects(t *testing.T) {
	state := installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-alloc"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	for _, dir := range []string{r.dir, r.workspaceDir, r.evidenceDir} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			t.Fatalf("missing run path %q: %v", dir, err)
		}
	}
	if info, err := os.Stat(r.rawPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("raw records file: %v", err)
	}
	if filepath.Dir(r.workspaceDir) != r.dir || filepath.Dir(r.evidenceDir) != r.dir || r.workspaceDir == r.evidenceDir {
		t.Fatalf("workspace and evidence are not separate siblings: %q vs %q", r.workspaceDir, r.evidenceDir)
	}
	if calls := dockerCalls(t, state); len(calls) != 0 {
		t.Fatalf("Prepare invoked docker: %v", calls)
	}
}

func TestStartRunsIsolatedContainerOnPerRunNetwork(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-abc"), testPlan(t, "alpine:3.21", "sh", "-c", "echo hi"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	started, err := b.Start(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if started.RunID != "run-abc" || started.StartedAt.IsZero() {
		t.Fatalf("StartedRun = %#v", started)
	}
	name := onlyContainer(t, state)
	if !strings.HasPrefix(name, "htb-run-abc-") {
		t.Fatalf("container name %q lacks run-bound prefix", name)
	}
	network := onlyNetwork(t, state)
	if !strings.HasPrefix(network, "htb-") || !strings.Contains(network, "run-abc") || network == name {
		t.Fatalf("network name %q is not a distinct per-run resource", network)
	}
	args := runArgs(t, state, name)
	for _, want := range []string{
		"--detach", "--name=" + name, "--runtime=runsc-benchmark", "--network=" + network,
		"--pull=never", "--user=10001:10001", "--cap-drop=ALL",
		"--security-opt=no-new-privileges", "--workdir=/workspace",
	} {
		if !containsArg(args, want) {
			t.Fatalf("docker run argv %v lacks %q", args, want)
		}
	}
	gatewayEnv := []string{"--env=http_proxy=", "--env=https_proxy=", "--env=HTTP_PROXY=", "--env=HTTPS_PROXY=", "--env=NODE_EXTRA_CA_CERTS=", "--env=SSL_CERT_FILE="}
	var mounts []string
	for _, a := range args {
		if strings.HasPrefix(a, "--mount=") {
			mounts = append(mounts, a)
		}
		envAllowed := false
		for _, prefix := range gatewayEnv {
			if strings.HasPrefix(a, prefix) {
				envAllowed = true
			}
		}
		if a == "-e" || a == "-u" || a == "-v" || a == "--privileged" ||
			(strings.HasPrefix(a, "--env") && !envAllowed) || strings.HasPrefix(a, "--volume") ||
			(strings.HasPrefix(a, "--user") && a != "--user=10001:10001") ||
			strings.Contains(a, "docker.sock") || strings.Contains(a, "seccheck") {
			t.Fatalf("docker run argv %v contains forbidden option %q", args, a)
		}
	}
	if len(mounts) != 3 || !strings.Contains(mounts[0], "type=bind") ||
		!strings.Contains(mounts[0], "src="+r.workspaceDir) || !strings.Contains(mounts[0], "dst=/workspace") ||
		!strings.Contains(mounts[1], "src="+r.resolverFile) || !strings.Contains(mounts[1], "dst=/etc/resolv.conf") || !strings.Contains(mounts[1], "readonly") ||
		!strings.Contains(mounts[2], "dst=/etc/benchmark/mitmproxy-ca-cert.pem") || !strings.Contains(mounts[2], "readonly") ||
		strings.Contains(mounts[1], "dst=/home/mitmproxy") || strings.Contains(mounts[2], "dst=/home/mitmproxy") {
		t.Fatalf("expected workspace bind plus readonly resolver and public CA mounts, got %v", mounts)
	}
	image := indexArg(args, "alpine:3.21")
	if image < 0 || !equalArgs(args[image+1:], []string{"sh", "-c", "echo hi"}) {
		t.Fatalf("image/command tail = %v", args)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 || exit.Reason != "exited" {
		t.Fatalf("Wait() = %#v, %v", exit, err)
	}
}

func containsArg(args []string, want string) bool { return indexArg(args, want) >= 0 }
func indexArg(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}
func equalArgs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestWaitReportsNonzeroWorkloadExit(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("7"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-nonzero"), testPlan(t, "alpine:3.21", "sh", "-c", "exit 7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil {
		t.Fatalf("nonzero workload exit treated as backend failure: %v", err)
	}
	if exit.Code != 7 || exit.Reason != "exited" || exit.ExitedAt.IsZero() {
		t.Fatalf("Wait() = %#v", exit)
	}
}

func TestStopTerminatesAndDestroyCleansUp(t *testing.T) {
	state := installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-stop"), testPlan(t, "alpine:3.21", "sh", "-c", "sleep 60"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	name := onlyContainer(t, state)
	network := onlyNetwork(t, state)
	if err := b.Stop(context.Background(), h, "test-stop"); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Reason != "stopped" {
		t.Fatalf("Wait() after Stop = %#v, %v", exit, err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"container-" + name, "network-" + network} {
		if _, err := os.Stat(filepath.Join(state, marker)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("docker resource %q survived Destroy", marker)
		}
	}
	if _, err := os.Stat(r.workspaceDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace survived Destroy: %v", err)
	}
	if _, err := os.Stat(r.evidenceDir); err != nil {
		t.Fatalf("evidence directory was not retained: %v", err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatalf("second Destroy = %v", err)
	}
	if _, err := b.Wait(context.Background(), h); err == nil {
		t.Fatal("destroyed handle accepted")
	}
}

func TestDestroyStopsRunningRun(t *testing.T) {
	state := installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-destroy"), testPlan(t, "alpine:3.21", "sh", "-c", "sleep 60"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	name := onlyContainer(t, state)
	network := onlyNetwork(t, state)
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "gone-"+name)); err != nil {
		t.Fatalf("container %q was not removed", name)
	}
	if _, err := os.Stat(filepath.Join(state, "network-"+network)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("network %q survived Destroy", network)
	}
	if _, err := os.Stat(r.workspaceDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace survived Destroy: %v", err)
	}
	if _, err := os.Stat(r.evidenceDir); err != nil {
		t.Fatalf("evidence directory was not retained: %v", err)
	}
}

func TestDestroyRetriesAfterContainerRemovalFailure(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-retryrm"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	name := onlyContainer(t, state)
	if err := os.WriteFile(filepath.Join(state, "fail-rm"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.Destroy(context.Background(), h); err == nil {
		t.Fatal("Destroy succeeded despite container removal failure")
	}
	if _, err := os.Stat(filepath.Join(state, "container-"+name)); err != nil {
		t.Fatalf("container marker lost while removal failed: %v", err)
	}
	if !r.containerCreated || r.networkCreated || r.workspaceExists {
		t.Fatalf("outstanding resource flags not preserved: %#v", r)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatalf("handle not recoverable after failed Destroy: %v", err)
	}
	if _, err := b.Start(context.Background(), h); err == nil {
		t.Fatal("Start succeeded on a run with outstanding cleanup")
	}
	if err := os.Remove(filepath.Join(state, "fail-rm")); err != nil {
		t.Fatal(err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatalf("Destroy retry = %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "gone-"+name)); err != nil {
		t.Fatalf("container %q not removed on retry", name)
	}
	if _, err := os.Stat(r.workspaceDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace survived Destroy: %v", err)
	}
	if _, err := os.Stat(r.evidenceDir); err != nil {
		t.Fatalf("evidence directory was not retained: %v", err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatalf("second Destroy = %v", err)
	}
	if _, err := b.Wait(context.Background(), h); err == nil {
		t.Fatal("destroyed handle accepted")
	}
}

func TestDestroyRetriesAfterNetworkRemovalFailure(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-retrynet"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	name := onlyContainer(t, state)
	network := onlyNetwork(t, state)
	if err := os.WriteFile(filepath.Join(state, "fail-network-rm"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.Destroy(context.Background(), h); err == nil {
		t.Fatal("Destroy succeeded despite network removal failure")
	}
	if _, err := os.Stat(filepath.Join(state, "gone-"+name)); err != nil {
		t.Fatalf("container %q was not removed", name)
	}
	if _, err := os.Stat(filepath.Join(state, "network-"+network)); err != nil {
		t.Fatalf("network marker lost while removal failed: %v", err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatalf("handle not recoverable after failed Destroy: %v", err)
	}
	if err := os.Remove(filepath.Join(state, "fail-network-rm")); err != nil {
		t.Fatal(err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatalf("Destroy retry = %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "network-"+network)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("network %q survived retry", network)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatalf("second Destroy = %v", err)
	}
}

func TestDestroyPreparedRunUsesNoDockerCalls(t *testing.T) {
	state := installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-prepared"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	for _, line := range dockerCalls(t, state) {
		if strings.Contains(line, "run-prepared") {
			t.Fatalf("Destroy of a prepared run invoked docker: %v", dockerCalls(t, state))
		}
	}
	if _, err := os.Stat(r.workspaceDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace survived Destroy: %v", err)
	}
	if _, err := os.Stat(r.evidenceDir); err != nil {
		t.Fatalf("evidence directory was not retained: %v", err)
	}
}

func TestStartContainerFailureCleansPartialResources(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "fail-run"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-fail"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err == nil {
		t.Fatal("Start succeeded")
	}
	var sawRemove, sawNetworkRemove bool
	var networkName string
	for _, line := range dockerCalls(t, state) {
		if strings.HasPrefix(line, "docker network create ") {
			networkName = strings.TrimPrefix(line, "docker network create ")
		}
		if strings.HasPrefix(line, "docker rm --force ") {
			sawRemove = true
		}
		if strings.HasPrefix(line, "docker network rm ") {
			sawNetworkRemove = true
		}
	}
	if networkName == "" || !sawRemove || !sawNetworkRemove {
		t.Fatalf("partial start was not cleaned up: %v", dockerCalls(t, state))
	}
	matches, _ := filepath.Glob(filepath.Join(state, "network-*"))
	if len(matches) != 0 {
		t.Fatalf("network marker survived cleanup: %v", matches)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestStartNetworkFailureDoesNotRunContainer(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "fail-network-create"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-netfail"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err == nil {
		t.Fatal("Start succeeded")
	}
	for _, line := range dockerCalls(t, state) {
		if strings.HasPrefix(line, "docker run ") {
			t.Fatalf("container was started despite network failure: %v", line)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(state, "network-*"))
	if len(matches) != 0 {
		t.Fatalf("network marker exists: %v", matches)
	}
}

func TestLifecycleRejectsInvalidStatesAndHandles(t *testing.T) {
	installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-states"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err == nil {
		t.Fatal("Wait before Start succeeded")
	}
	if _, _, err := b.FinalizeEvidence(context.Background(), h); err == nil {
		t.Fatal("FinalizeEvidence before Start succeeded")
	}
	if _, err := b.Prepare(context.Background(), testSpec("run-states"), testPlan(t, "alpine:3.21", "true")); err == nil {
		t.Fatal("duplicate Prepare succeeded")
	}
	if _, err := b.Start(context.Background(), fakeHandle("run-foreign")); err == nil {
		t.Fatal("foreign handle accepted")
	}
	if err := b.Stop(context.Background(), h, "not-started"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err == nil {
		t.Fatal("Start after Stop succeeded")
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Snapshot(context.Background(), h); err == nil {
		t.Fatal("destroyed handle accepted")
	}
}

func TestWaitHonorsContextCancellation(t *testing.T) {
	installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-cancel"), testPlan(t, "alpine:3.21", "sh", "-c", "sleep 60"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := b.Wait(ctx, h); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait cancellation = %v", err)
	}
	if err := b.Stop(context.Background(), h, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestDescribeReportsHonestCapabilities(t *testing.T) {
	installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	m, err := b.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if m.Digest == "" {
		t.Fatal("manifest digest missing")
	}
	byFamily := map[string]backend.Capability{}
	for _, c := range m.Capabilities {
		byFamily[c.EventFamily] = c
	}
	for _, family := range []string{"process", "workload/stdout", "workload/stderr", "filesystem", "dns", "network/packets", "network/config", "network/flow", "network/plaintext"} {
		c, ok := byFamily[family]
		if !ok || c.Observation != backend.ObservationBestEffort || c.Enforcement != backend.EnforcementAuditOnly {
			t.Fatalf("capability %q is dishonest: %#v", family, c)
		}
	}
}

func TestFinalizeEvidenceChainsLifecycleRecords(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-evidence"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	snapshot, err := b.Snapshot(context.Background(), h)
	if err != nil || snapshot.Digest == "" {
		t.Fatalf("Snapshot() = %#v, %v", snapshot, err)
	}
	evidenceOut, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := healthSource(t, health, sensorID)
	if !lifecycle.Started || !lifecycle.Drained || !lifecycle.Stopped {
		t.Fatalf("health = %#v", health)
	}
	if lifecycle.PlaintextFailures != 1 {
		t.Fatalf("health does not record unsupported plaintext capture: %#v", health)
	}
	if len(health.Sources) != len(sourceOrder) {
		t.Fatalf("health sources = %v", health.Sources)
	}
	if evidenceOut.RawChainHeads[sensorID] == "" || len(evidenceOut.RawChainHeads) != len(sourceOrder) {
		t.Fatalf("evidence = %#v", evidenceOut)
	}
	var foundRaw bool
	for _, id := range evidenceOut.ArtifactIDs {
		if id == "raw-records.bin" {
			foundRaw = true
		}
	}
	if !foundRaw {
		t.Fatalf("artifacts = %v", evidenceOut.ArtifactIDs)
	}
	src := r.sources[sensorID]
	head, err := evidence.ValidateChain(src.records, src.seed)
	if err != nil || head != evidenceOut.RawChainHeads[sensorID] {
		t.Fatalf("raw chain = %q, %v", head, err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.rawPath); err != nil {
		t.Fatalf("raw evidence was not retained after Destroy: %v", err)
	}
}

func healthSource(t *testing.T, health backend.SensorHealth, id string) backend.SensorSourceHealth {
	t.Helper()
	for _, s := range health.Sources {
		if s.SensorID == id {
			return s
		}
	}
	t.Fatalf("missing health source %q in %#v", id, health.Sources)
	return backend.SensorSourceHealth{}
}

type fakeHandle string

func (f fakeHandle) RunID() string { return string(f) }

func tarContents(t *testing.T, path string) map[string]*tar.Header {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]*tar.Header{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		copy := *hdr
		out[strings.TrimPrefix(hdr.Name, "./")] = &copy
	}
}

func tarFileBody(t *testing.T, path, name string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err != nil {
			t.Fatalf("entry %q not found in %s: %v", name, path, err)
		}
		if strings.TrimPrefix(hdr.Name, "./") == name {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
}

func TestWorkloadOutputCapturedAsSeparateArtifacts(t *testing.T) {
	state := installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-logs"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if err := os.WriteFile(filepath.Join(r.workspaceDir, "probe.txt"), []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	name := onlyContainer(t, state)
	stdout := []byte("EXACT-OUT\x00binary-bytes")
	stderr := []byte("EXACT-ERR\n")
	if err := os.WriteFile(filepath.Join(state, "logs-out-"+name), stdout, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "logs-err-"+name), stderr, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "exit-"+name), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 || exit.Reason != "exited" {
		t.Fatalf("Wait = %#v, %v", exit, err)
	}
	gotOut, err := os.ReadFile(r.stdoutPath)
	if err != nil || !bytes.Equal(gotOut, stdout) {
		t.Fatalf("stdout.log = %q, %v", gotOut, err)
	}
	gotErr, err := os.ReadFile(r.stderrPath)
	if err != nil || !bytes.Equal(gotErr, stderr) {
		t.Fatalf("stderr.log = %q, %v", gotErr, err)
	}
	for _, path := range []string{r.stdoutPath, r.stderrPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}
	type artifactMeta struct {
		Artifact string `json:"artifact"`
		SHA256   string `json:"sha256"`
		Size     uint64 `json:"size"`
	}
	for _, tc := range []struct {
		source string
		data   []byte
	}{{sourceStdout, stdout}, {sourceStderr, stderr}} {
		src := r.sources[tc.source]
		if len(src.records) != 1 || src.records[0].SensorID != tc.source || src.records[0].SourceSeq != 1 {
			t.Fatalf("%s records = %#v", tc.source, src.records)
		}
		var meta artifactMeta
		if err := json.Unmarshal(src.records[0].Payload, &meta); err != nil {
			t.Fatal(err)
		}
		if meta.SHA256 != backend.SHA256Hex(tc.data) || meta.Size != uint64(len(tc.data)) || !strings.HasSuffix(meta.Artifact, ".log") {
			t.Fatalf("%s metadata = %#v", tc.source, meta)
		}
	}
	if r.sources[sourceStdout].bootID == r.sources[sourceStderr].bootID {
		t.Fatal("stdout and stderr share a boot ID")
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceSnapshotsBeforeAndAfter(t *testing.T) {
	state := installFakeSudo(t)
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-snap"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if err := os.WriteFile(filepath.Join(r.workspaceDir, "probe.txt"), []byte("before-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("probe.txt", filepath.Join(r.workspaceDir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	name := onlyContainer(t, state)
	if err := os.WriteFile(filepath.Join(r.workspaceDir, "during.txt"), []byte("after-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "exit-"+name), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	before := filepath.Join(r.evidenceDir, "workspace-before.tar")
	after := filepath.Join(r.evidenceDir, "workspace-after.tar")
	beforeEntries := tarContents(t, before)
	afterEntries := tarContents(t, after)
	if _, ok := beforeEntries["probe.txt"]; !ok {
		t.Fatalf("before snapshot missing probe.txt: %v", beforeEntries)
	}
	if _, ok := beforeEntries["during.txt"]; ok {
		t.Fatal("before snapshot contains during.txt")
	}
	if _, ok := afterEntries["during.txt"]; !ok {
		t.Fatalf("after snapshot missing during.txt: %v", afterEntries)
	}
	link, ok := beforeEntries["link.txt"]
	if !ok || link.Typeflag != tar.TypeSymlink || link.Linkname != "probe.txt" {
		t.Fatalf("before snapshot link.txt = %#v", link)
	}
	if body := tarFileBody(t, before, "probe.txt"); body != "before-content" {
		t.Fatalf("before probe.txt body = %q", body)
	}
	if body := tarFileBody(t, after, "during.txt"); body != "after-content" {
		t.Fatalf("after during.txt body = %q", body)
	}
	for _, src := range []*sourceState{r.sources[sourceBefore], r.sources[sourceAfter]} {
		if len(src.records) != 1 {
			t.Fatalf("%s records = %#v", src.id, src.records)
		}
	}
	for _, path := range []string{before, after} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode/err = %v, %v", path, info, err)
		}
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestCollectsOnlyThisRunRunscLogs(t *testing.T) {
	state := installFakeSudo(t)
	runscDir := t.TempDir()
	t.Setenv("FAKE_RUNSC_DIR", runscDir)
	otherID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(runscDir, "runsc."+otherID+".boot.log"), []byte("other run"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-runsc"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	name := onlyContainer(t, state)
	idBytes, err := os.ReadFile(filepath.Join(state, "id-"+name))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(idBytes))
	if err := os.WriteFile(filepath.Join(state, "exit-"+name), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"boot.log", "gofer.log"} {
		path := filepath.Join(r.evidenceDir, "runsc."+id+"."+suffix)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s stat = %v, %v", path, info, err)
		}
	}
	for _, unwanted := range []string{"runsc." + id + ".notes.txt", "runsc." + otherID + ".boot.log"} {
		if _, err := os.Stat(filepath.Join(r.evidenceDir, unwanted)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("collected unrelated artifact %q", unwanted)
		}
	}
	src := r.sources[sourceRunsc]
	if len(src.records) != 2 {
		t.Fatalf("runsc records = %#v", src.records)
	}
	for i, record := range src.records {
		if record.SourceSeq != uint64(i+1) || record.SensorID != sourceRunsc || record.BootID != src.bootID {
			t.Fatalf("runsc record = %#v", record)
		}
		var meta struct {
			Artifact string `json:"artifact"`
			SHA256   string `json:"sha256"`
			Size     uint64 `json:"size"`
		}
		if err := json.Unmarshal(record.Payload, &meta); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(r.evidenceDir, meta.Artifact))
		if err != nil {
			t.Fatal(err)
		}
		if meta.SHA256 != backend.SHA256Hex(data) || meta.Size != uint64(len(data)) {
			t.Fatalf("runsc metadata = %#v for %q", meta, meta.Artifact)
		}
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorFailuresDegradeHealthNotWorkload(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", filepath.Join(t.TempDir(), "absent"))
	for _, marker := range []string{"fail-logs", "fail-tar", "fail-stats"} {
		if err := os.WriteFile(filepath.Join(state, marker), []byte("1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-degraded"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 || exit.Reason != "exited" {
		t.Fatalf("Wait = %#v, %v", exit, err)
	}
	evidenceOut, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{sourceStdout, sourceStderr, sourceBefore, sourceAfter, sourceRunsc, sourceResource} {
		s := healthSource(t, health, id)
		if s.Started || s.Stopped || s.Drained || s.Drops == 0 {
			t.Fatalf("degraded source %s health = %#v", id, s)
		}
	}
	lifecycle := healthSource(t, health, sensorID)
	if !lifecycle.Started || !lifecycle.Drained || !lifecycle.Stopped {
		t.Fatalf("lifecycle health = %#v", lifecycle)
	}
	for _, absent := range []string{"stdout.log", "stderr.log", "workspace-before.tar", "workspace-after.tar"} {
		for _, id := range evidenceOut.ArtifactIDs {
			if id == absent {
				t.Fatalf("artifact %q retained despite collector failure", absent)
			}
		}
		if _, err := os.Stat(filepath.Join(r.evidenceDir, absent)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("artifact %q exists despite collector failure: %v", absent, err)
		}
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestMissingRunscLogsDegradeHealthNotWorkload(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", filepath.Join(t.TempDir(), "absent"))
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-missing"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 {
		t.Fatalf("Wait = %#v, %v", exit, err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	s := healthSource(t, health, sourceRunsc)
	if s.Started || s.Drops != 1 {
		t.Fatalf("runsc health = %#v", s)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestResourceSamplerRecordsAndDrains(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-stats"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.samplerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("resource sampler did not drain")
	}
	src := r.sources[sourceResource]
	if len(src.records) < 2 {
		t.Fatalf("resource samples = %#v", src.records)
	}
	name := onlyContainer(t, state)
	for i, record := range src.records {
		if record.SourceSeq != uint64(i+1) || record.RecordType != "resource/sample" || !strings.Contains(string(record.Payload), name) {
			t.Fatalf("resource record = %#v", record)
		}
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	s := healthSource(t, health, sourceResource)
	if !s.Started || !s.Drained || !s.Stopped || s.Drops != 0 {
		t.Fatalf("resource health = %#v", s)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestRawRecordsDefensiveCopyAndRunDirectory(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-raw"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	dir, err := b.RunDirectory(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if dir != r.evidenceDir || dir == r.workspaceDir {
		t.Fatalf("RunDirectory = %q", dir)
	}
	records, err := b.RawRecords(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	var total int
	for _, src := range r.sources {
		total += len(src.records)
	}
	if len(records) != total {
		t.Fatalf("RawRecords = %d, want %d", len(records), total)
	}
	first := records[0].Payload[0]
	wall := *records[0].ObservedWallTime
	records[0].Payload[0] ^= 0xff
	records[0].RecordSHA256 = "tampered"
	*records[0].ObservedWallTime = time.Time{}
	mono := uint64(42)
	records[0].ObservedMonotonicNS = &mono
	again, err := b.RawRecords(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Payload[0] != first || again[0].RecordSHA256 == "tampered" {
		t.Fatal("RawRecords exposes internal state")
	}
	if again[0].ObservedWallTime == nil || !again[0].ObservedWallTime.Equal(wall) || again[0].ObservedMonotonicNS != nil {
		t.Fatal("RawRecords exposes mutable time fields")
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.RawRecords(context.Background(), h); err == nil {
		t.Fatal("RawRecords succeeded on destroyed handle")
	}
	if _, err := b.RunDirectory(context.Background(), h); err == nil {
		t.Fatal("RunDirectory succeeded on destroyed handle")
	}
}

func TestSourceChainsIndependent(t *testing.T) {
	state := installFakeSudo(t)
	runscDir := t.TempDir()
	t.Setenv("FAKE_RUNSC_DIR", runscDir)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-chains"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	evidenceOut, _, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	bootIDs := map[string]bool{}
	heads := map[string]bool{}
	for _, id := range sourceOrder {
		src := r.sources[id]
		if src.bootID == "" || bootIDs[src.bootID] {
			t.Fatalf("source %s boot ID %q is not unique", id, src.bootID)
		}
		bootIDs[src.bootID] = true
		for i, record := range src.records {
			if record.SourceSeq != uint64(i+1) || record.SensorID != id || record.BootID != src.bootID {
				t.Fatalf("source %s record = %#v", id, record)
			}
		}
		head, err := evidence.ValidateChain(src.records, src.seed)
		if err != nil {
			t.Fatalf("source %s chain: %v", id, err)
		}
		if evidenceOut.RawChainHeads[id] != head {
			t.Fatalf("source %s head = %q, evidence = %q", id, head, evidenceOut.RawChainHeads[id])
		}
		if len(src.records) > 0 && heads[head] {
			t.Fatalf("sources share chain head %q", head)
		}
		heads[head] = true
	}
	src := r.sources[sensorID]
	tampered := append([]evidence.RawRecord(nil), src.records...)
	tampered[0].Payload = append([]byte(nil), tampered[0].Payload...)
	tampered[0].Payload[0] ^= 0xff
	if _, err := evidence.ValidateChain(tampered, src.seed); err == nil {
		t.Fatal("tampered lifecycle chain validated")
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestStartRejectsAmbiguousContainerID(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "bad-id"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-badid"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err == nil || !strings.Contains(err.Error(), "cannot attribute runsc logs") {
		t.Fatalf("Start = %v", err)
	}
	if r.containerID != "" {
		t.Fatalf("containerID = %q", r.containerID)
	}
	calls := strings.Join(dockerCalls(t, state), "\n")
	if !strings.Contains(calls, "docker rm --force "+r.containerName) || !strings.Contains(calls, "docker network rm "+r.networkName) {
		t.Fatalf("cleanup calls = %s", calls)
	}
}

func TestWaitFailureAccountsLifecycleDrop(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "wait-fails"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-waitfail"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != -1 || exit.Reason != "failed" {
		t.Fatalf("Wait = %#v, %v", exit, err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := healthSource(t, health, sensorID)
	if lifecycle.Drops != 1 || lifecycle.ParseFailures != 0 {
		t.Fatalf("lifecycle health = %#v", lifecycle)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestWaitGarbageAccountsLifecycleParseFailure(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "wait-garbage"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-waitgarbage"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != -1 {
		t.Fatalf("Wait = %#v, %v", exit, err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := healthSource(t, health, sensorID)
	if lifecycle.ParseFailures != 1 || lifecycle.Drops != 0 {
		t.Fatalf("lifecycle health = %#v", lifecycle)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestStartCleanupFailureLeavesRecoverableDestroyingRun(t *testing.T) {
	state := installFakeSudo(t)
	for _, marker := range []string{"fail-run", "fail-rm"} {
		if err := os.WriteFile(filepath.Join(state, marker), []byte("1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-leak"), testPlan(t, "alpine:3.21", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err == nil {
		t.Fatal("Start succeeded")
	}
	if r.state != stateDestroying {
		t.Fatalf("state = %s, want destroying", r.state)
	}
	if !r.containerCreated || r.networkCreated {
		t.Fatalf("outstanding cleanup flags = container:%v network:%v", r.containerCreated, r.networkCreated)
	}
	if _, err := b.Start(context.Background(), h); err == nil {
		t.Fatal("second Start succeeded on a run with leaked resources")
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != -1 {
		t.Fatalf("Wait = %#v, %v", exit, err)
	}
	if err := b.Destroy(context.Background(), h); err == nil {
		t.Fatal("Destroy succeeded while container removal still fails")
	}
	if !r.containerCreated {
		t.Fatal("container cleanup flag cleared despite failed removal")
	}
	if err := os.Remove(filepath.Join(state, "fail-rm")); err != nil {
		t.Fatal(err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatalf("retry Destroy: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(state, "container-*"))
	if len(matches) != 0 {
		t.Fatalf("container marker survived destroy: %v", matches)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func TestStartSurvivesRawAppendFailure(t *testing.T) {
	state := installFakeSudo(t)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-append-loss"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if err := os.Chmod(r.rawPath, 0o400); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(r.rawPath, 0o600) }()
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 || exit.Reason != "exited" {
		t.Fatalf("Wait() = %#v, %v", exit, err)
	}
	if err := os.Chmod(r.rawPath, 0o600); err != nil {
		t.Fatal(err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatalf("FinalizeEvidence() = %v", err)
	}
	var lifecycle *backend.SensorSourceHealth
	for i := range health.Sources {
		if health.Sources[i].SensorID == sensorID {
			lifecycle = &health.Sources[i]
		}
	}
	if lifecycle == nil || lifecycle.ParseFailures == 0 {
		t.Fatalf("lifecycle health does not expose spool loss: %#v", health.Sources)
	}
}

func TestSeccheckFramesCapturedAndChained(t *testing.T) {
	state := installFakeSudo(t)
	seccheckDir := t.TempDir()
	t.Setenv("FAKE_SECCHECK_DIR", seccheckDir)
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "seccheck-status"), []byte("{\"frames\":2,\"oversize\":1,\"reportedDrops\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-seccheck"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 {
		t.Fatalf("Wait() = %#v, %v", exit, err)
	}
	frames, err := os.ReadFile(filepath.Join(r.evidenceDir, "seccheck.frames"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "\x00\x00\x00\x04ABCD\x00\x00\x00\x03XYZ"; string(frames) != want {
		t.Fatalf("seccheck.frames = %q", frames)
	}
	status, err := os.ReadFile(filepath.Join(r.evidenceDir, "seccheck.done"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(status); got != "{\"frames\":2,\"oversize\":1,\"reportedDrops\":1}\n" {
		t.Fatalf("seccheck.done = %q", got)
	}
	raw, err := b.RawRecords(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	var seccheck []evidence.RawRecord
	for _, record := range raw {
		if record.SensorID == sourceSeccheck && record.RecordType == "seccheck/frame" {
			seccheck = append(seccheck, record)
		}
	}
	if len(seccheck) != 2 || string(seccheck[0].Payload) != "ABCD" || string(seccheck[1].Payload) != "XYZ" {
		t.Fatalf("seccheck frames = %#v", seccheck)
	}
	if seccheck[0].Encoding != "protobuf" || seccheck[0].SourceSeq != 1 || seccheck[1].SourceSeq != 2 || seccheck[1].PreviousRecordSHA256 != seccheck[0].RecordSHA256 {
		t.Fatalf("seccheck chain fields = %#v", seccheck)
	}
	evidenceOut, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	var src *backend.SensorSourceHealth
	for i := range health.Sources {
		if health.Sources[i].SensorID == sourceSeccheck {
			src = &health.Sources[i]
		}
	}
	if src == nil || !src.Started || !src.Drained || !src.Stopped || src.Drops != 2 || src.ParseFailures != 0 {
		t.Fatalf("seccheck health = %#v", src)
	}
	found := map[string]bool{}
	for _, id := range evidenceOut.ArtifactIDs {
		found[id] = true
	}
	if !found["seccheck.frames"] || !found["seccheck.done"] {
		t.Fatalf("artifact IDs = %v", evidenceOut.ArtifactIDs)
	}
}

func TestSeccheckMissingStatusDegradesHealth(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_SECCHECK_DIR", filepath.Join(t.TempDir(), "absent"))
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-no-seccheck"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 || exit.Reason != "exited" {
		t.Fatalf("Wait() = %#v, %v", exit, err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	var src *backend.SensorSourceHealth
	for i := range health.Sources {
		if health.Sources[i].SensorID == sourceSeccheck {
			src = &health.Sources[i]
		}
	}
	if src == nil || src.Started || src.Drained || src.Drops < 1 {
		t.Fatalf("seccheck health = %#v", src)
	}
	if entries, err := filepath.Glob(filepath.Join(r.evidenceDir, "seccheck*")); err != nil || len(entries) != 0 {
		t.Fatalf("unexpected seccheck artifacts: %v", entries)
	}
}

func TestSeccheckCountMismatchRetainsPartial(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_SECCHECK_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "seccheck-status"), []byte("{\"frames\":5,\"oversize\":0,\"reportedDrops\":0}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-seccheck-mismatch"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 {
		t.Fatalf("Wait() = %#v, %v", exit, err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	var src *backend.SensorSourceHealth
	for i := range health.Sources {
		if health.Sources[i].SensorID == sourceSeccheck {
			src = &health.Sources[i]
		}
	}
	if src == nil || !src.Started || src.Drained || src.ParseFailures < 1 {
		t.Fatalf("seccheck health = %#v", src)
	}
	partial, err := os.ReadFile(filepath.Join(r.evidenceDir, "seccheck.partial"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "\x00\x00\x00\x04ABCD\x00\x00\x00\x03XYZ"; string(partial) != want {
		t.Fatalf("seccheck.partial = %q", partial)
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "seccheck.partial-status")); err != nil {
		t.Fatalf("seccheck.partial-status missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "seccheck.frames")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical frames retained despite mismatch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "seccheck.done")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical status retained despite mismatch: %v", err)
	}
}

func TestSeccheckTruncatedFrameRetainsPartial(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_SECCHECK_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "seccheck-frames"), []byte("\x00\x00\x00\x0aAB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "seccheck-status"), []byte("{\"frames\":1,\"oversize\":0,\"reportedDrops\":0}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-seccheck-trunc"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 {
		t.Fatalf("Wait() = %#v, %v", exit, err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	var src *backend.SensorSourceHealth
	for i := range health.Sources {
		if health.Sources[i].SensorID == sourceSeccheck {
			src = &health.Sources[i]
		}
	}
	if src == nil || src.Started || src.Drained || src.ParseFailures < 1 {
		t.Fatalf("seccheck health = %#v", src)
	}
	partial, err := os.ReadFile(filepath.Join(r.evidenceDir, "seccheck.partial"))
	if err != nil {
		t.Fatal(err)
	}
	if string(partial) != "\x00\x00\x00\x0aAB" {
		t.Fatalf("seccheck.partial = %q", partial)
	}
}

type netMeta struct {
	Artifact  string `json:"artifact"`
	SHA256    string `json:"sha256"`
	Size      uint64 `json:"size"`
	Interface string `json:"interface"`
	Direction string `json:"direction"`
	Phase     string `json:"phase"`
}

func findSource(t *testing.T, health backend.SensorHealth, id string) *backend.SensorSourceHealth {
	t.Helper()
	for i := range health.Sources {
		if health.Sources[i].SensorID == id {
			return &health.Sources[i]
		}
	}
	t.Fatalf("source %s missing from health %#v", id, health.Sources)
	return nil
}

func netRecords(t *testing.T, raw []evidence.RawRecord, source, recordType string) []netMeta {
	t.Helper()
	var metas []netMeta
	for _, record := range raw {
		if record.SensorID != source || record.RecordType != recordType {
			continue
		}
		var meta netMeta
		if err := json.Unmarshal(record.Payload, &meta); err != nil {
			t.Fatalf("record payload: %v", err)
		}
		metas = append(metas, meta)
	}
	return metas
}

func runSimpleWorkload(t *testing.T, state string) (*Backend, *run) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-net"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 {
		t.Fatalf("Wait() = %#v, %v", exit, err)
	}
	return b, r
}

func TestNetworkCapturesAndConfigRecorded(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	t.Setenv("FAKE_SECCHECK_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "tcpdump-drops"), []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if len(r.bridgeName) != 15 || !strings.HasPrefix(r.bridgeName, "br-") {
		t.Fatalf("bridge name = %q", r.bridgeName)
	}
	for _, name := range []string{"bridge-ingress.pcap", "bridge-egress.pcap", "veth-ingress.pcap", "veth-egress.pcap"} {
		if _, err := os.Stat(filepath.Join(r.evidenceDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
		for _, suffix := range []string{".stats", ".meta"} {
			if _, err := os.Stat(filepath.Join(r.evidenceDir, name+suffix)); err != nil {
				t.Fatalf("missing %s%s: %v", name, suffix, err)
			}
		}
	}
	if got, err := os.ReadFile(filepath.Join(r.evidenceDir, "bridge-ingress.pcap")); err != nil || string(got) != "PCAP:"+r.bridgeName+":in\n" {
		t.Fatalf("bridge-ingress.pcap = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(r.evidenceDir, "veth-egress.pcap")); err != nil || string(got) != "PCAP:veth7f3a99:out\n" {
		t.Fatalf("veth-egress.pcap = %q, %v", got, err)
	}
	for _, name := range []string{"net-inspect-start.json", "net-inspect-stop.json", "bridge-addr-start.json", "bridge-addr-stop.json", "route-start.json", "route-stop.json", "bridge-link-start.txt", "bridge-link-stop.txt", "iptables-start.txt", "iptables-stop.txt", "nft-start.txt", "nft-stop.txt", "eth0-addr-start.json", "eth0-route-start.json"} {
		if _, err := os.Stat(filepath.Join(r.evidenceDir, name)); err != nil {
			t.Fatalf("missing config artifact %s: %v", name, err)
		}
	}
	raw, err := b.RawRecords(context.Background(), h2h(t, b, r))
	if err != nil {
		t.Fatal(err)
	}
	bridgePackets := netRecords(t, raw, sourcePacketsBridge, "network/packet")
	vethPackets := netRecords(t, raw, sourcePacketsVeth, "network/packet")
	if len(bridgePackets) != 2 || len(vethPackets) != 2 {
		t.Fatalf("packet records: bridge=%v veth=%v", bridgePackets, vethPackets)
	}
	seen := map[string]netMeta{}
	for _, m := range append(bridgePackets, vethPackets...) {
		if m.Interface == "" || (m.Direction != "ingress" && m.Direction != "egress") || m.Phase != "" {
			t.Fatalf("packet meta = %#v", m)
		}
		content, err := os.ReadFile(filepath.Join(r.evidenceDir, m.Artifact))
		if err != nil {
			t.Fatal(err)
		}
		if got := backend.SHA256Hex(content); got != m.SHA256 || uint64(len(content)) != m.Size {
			t.Fatalf("artifact %s digest mismatch: %#v", m.Artifact, m)
		}
		seen[m.Artifact] = m
	}
	if seen["bridge-ingress.pcap"].Interface != r.bridgeName || seen["bridge-ingress.pcap"].Direction != "ingress" ||
		seen["bridge-egress.pcap"].Direction != "egress" || seen["veth-ingress.pcap"].Interface != "veth7f3a99" {
		t.Fatalf("packet meta directions/interfaces = %#v", seen)
	}
	configs := netRecords(t, raw, sourceNetConfig, "network/config")
	if len(configs) != 14 {
		t.Fatalf("config records = %#v", configs)
	}
	phases := map[string]int{}
	for _, m := range configs {
		if m.Interface == "" || m.Direction != "" || (m.Phase != "start" && m.Phase != "stop") {
			t.Fatalf("config meta = %#v", m)
		}
		phases[m.Phase]++
	}
	if phases["start"] != 8 || phases["stop"] != 6 {
		t.Fatalf("config phases = %#v", phases)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), h2h(t, b, r))
	if err != nil {
		t.Fatal(err)
	}
	bridge := findSource(t, health, sourcePacketsBridge)
	if !bridge.Started || !bridge.Drained || !bridge.Stopped || bridge.Drops != 4 || bridge.ParseFailures != 0 {
		t.Fatalf("bridge health = %#v", bridge)
	}
	veth := findSource(t, health, sourcePacketsVeth)
	if !veth.Started || !veth.Drained || !veth.Stopped || veth.Drops != 4 || veth.StreamGaps != 1 {
		t.Fatalf("veth health = %#v", veth)
	}
	config := findSource(t, health, sourceNetConfig)
	if !config.Started || config.Drained || config.Stopped || config.Drops != 2 {
		t.Fatalf("config health = %#v", config)
	}
}

func h2h(t *testing.T, b *Backend, r *run) backend.RunHandle {
	t.Helper()
	return r
}

func TestNetworkVethMismatchDegradesSource(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	t.Setenv("FAKE_SECCHECK_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "veth-wrongmaster"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if entries, _ := filepath.Glob(filepath.Join(r.evidenceDir, "veth-*.pcap")); len(entries) != 0 {
		t.Fatalf("unexpected veth captures: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "bridge-ingress.pcap")); err != nil {
		t.Fatalf("bridge capture missing: %v", err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	veth := findSource(t, health, sourcePacketsVeth)
	if veth.Started || veth.Drained || veth.Drops < 1 {
		t.Fatalf("veth health = %#v", veth)
	}
	bridge := findSource(t, health, sourcePacketsBridge)
	if !bridge.Started || !bridge.Drained || bridge.Drops != 0 {
		t.Fatalf("bridge health = %#v", bridge)
	}
}

func TestNetworkVethDuplicateMatchDegradesSource(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "veth-dup"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := runSimpleWorkload(t, state)
	_, health, err := b.FinalizeEvidence(context.Background(), mustHandle(t, b, "run-net"))
	if err != nil {
		t.Fatal(err)
	}
	veth := findSource(t, health, sourcePacketsVeth)
	if veth.Started || veth.Drained || veth.Drops < 1 {
		t.Fatalf("veth health = %#v", veth)
	}
}

func mustHandle(t *testing.T, b *Backend, runID string) backend.RunHandle {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.runs[runID]
	if !ok {
		t.Fatalf("run %s not registered", runID)
	}
	return r
}

func TestNetworkTcpdumpFailureCompletesWorkload(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "fail-tcpdump"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "bridge-ingress.pcap")); err != nil {
		t.Fatalf("bridge pcap not retained: %v", err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{sourcePacketsBridge, sourcePacketsVeth} {
		src := findSource(t, health, id)
		if src.Drained || src.Stopped || src.Drops < 1 || src.ParseFailures < 1 {
			t.Fatalf("%s health = %#v", id, src)
		}
	}
}

func TestNetworkMissingStatsParseFailure(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "tcpdump-nostats"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "bridge-ingress.pcap")); err != nil {
		t.Fatalf("bridge capture missing: %v", err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	bridge := findSource(t, health, sourcePacketsBridge)
	if !bridge.Started || bridge.Drained || bridge.ParseFailures < 1 {
		t.Fatalf("bridge health = %#v", bridge)
	}
}

func TestNetworkCaptureDrainTimeoutKills(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "tcpdump-hang"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := runSimpleWorkload(t, state)
	_, health, err := b.FinalizeEvidence(context.Background(), mustHandle(t, b, "run-net"))
	if err != nil {
		t.Fatal(err)
	}
	bridge := findSource(t, health, sourcePacketsBridge)
	if !bridge.Started || bridge.Drained || bridge.Drops < 1 {
		t.Fatalf("bridge health = %#v", bridge)
	}
	heartbeat := filepath.Join(state, "hang-heartbeat")
	first, err := os.ReadFile(heartbeat)
	if err != nil {
		t.Fatalf("hang heartbeat missing: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	second, err := os.ReadFile(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("tcpdump child process group survived forced drain")
	}
}

func TestNetworkBridgeListenerTimeoutMarksGap(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "tcpdump-nolisten"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if got, err := os.ReadFile(filepath.Join(r.evidenceDir, "bridge-ingress.pcap")); err != nil || !strings.HasPrefix(string(got), "PCAP:") {
		t.Fatalf("bridge pcap = %q, %v", got, err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	bridge := findSource(t, health, sourcePacketsBridge)
	if !bridge.Started || bridge.Drained || bridge.Stopped || bridge.StreamGaps < 1 {
		t.Fatalf("bridge health = %#v", bridge)
	}
	veth := findSource(t, health, sourcePacketsVeth)
	if !veth.Started || !veth.Drained || veth.StreamGaps < 1 {
		t.Fatalf("veth health = %#v", veth)
	}
}

func TestNetworkSlowListenerStillReady(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "tcpdump-slow-listen"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	bridge := findSource(t, health, sourcePacketsBridge)
	if !bridge.Started || !bridge.Drained || !bridge.Stopped || bridge.Drops != 0 || bridge.StreamGaps != 0 {
		t.Fatalf("bridge health = %#v", bridge)
	}
}

func TestNetworkMissingNftDegradesConfig(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "fail-nft"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "nft-start.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nft artifact retained despite failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "iptables-start.txt")); err != nil {
		t.Fatalf("iptables artifact missing: %v", err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	config := findSource(t, health, sourceNetConfig)
	if !config.Started || config.Drained || config.Drops < 2 {
		t.Fatalf("config health = %#v", config)
	}
}

func TestNetworkConfigFailureDegradesSource(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "fail-iptables"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "iptables-start.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("iptables artifact retained despite failure: %v", err)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	config := findSource(t, health, sourceNetConfig)
	if !config.Started || config.Drained || config.Drops < 1 {
		t.Fatalf("config health = %#v", config)
	}
}

func TestGatewayCapturesFlowsAndDNS(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	t.Setenv("FAKE_SECCHECK_DIR", t.TempDir())
	b, r := runSimpleWorkload(t, state)
	if r.gatewayIP != "10.88.0.2" {
		t.Fatalf("gatewayIP = %q", r.gatewayIP)
	}
	runargs, err := os.ReadFile(filepath.Join(state, "runargs-"+r.containerName))
	if err != nil {
		t.Fatal(err)
	}
	args := string(runargs)
	for _, want := range []string{
		"--mount=type=bind,src=" + r.resolverFile + ",dst=/etc/resolv.conf,readonly",
		"--env=http_proxy=http://10.88.0.2:8080",
		"--env=https_proxy=http://10.88.0.2:8080",
		"--env=HTTP_PROXY=http://10.88.0.2:8080",
		"--env=HTTPS_PROXY=http://10.88.0.2:8080",
		"--env=NODE_EXTRA_CA_CERTS=/etc/benchmark/mitmproxy-ca-cert.pem",
		"--env=SSL_CERT_FILE=/etc/benchmark/mitmproxy-ca-cert.pem",
		",dst=/etc/benchmark/mitmproxy-ca-cert.pem,readonly",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("workload args missing %q:\n%s", want, args)
		}
	}
	if strings.Contains(args, "--dns=") || strings.Contains(args, "htb-gateway:8080") || strings.Contains(args, "mitmproxy-ca.pem") || strings.Contains(args, "dst=/home/mitmproxy") || strings.Contains(args, "PRIVATE KEY") {
		t.Fatalf("workload args use Docker DNS or leak private gateway material:\n%s", args)
	}
	resolver, err := os.ReadFile(r.resolverFile)
	if err != nil || string(resolver) != "nameserver 10.88.0.2\n" {
		t.Fatalf("resolver config = %q, %v", resolver, err)
	}
	resolverInfo, err := os.Stat(r.resolverFile)
	if err != nil || resolverInfo.Mode().Perm() != 0o644 {
		t.Fatalf("resolver permissions = %v, %v; workload uid must be able to read it", resolverInfo, err)
	}
	gwargs, err := os.ReadFile(filepath.Join(state, "runargs-"+r.proxyName))
	if err != nil {
		t.Fatal(err)
	}
	gw := string(gwargs)
	for _, want := range []string{"mitmproxy/mitmproxy:12.2.3@sha256:62d266a86ee95187217866c0e35487837498daa3aa1cdce37d256f07e198a47b", "--pull=never", "--network-alias=htb-gateway", "src=" + r.proxyDir, "regular@8080", "dns@53"} {
		if !strings.Contains(gw, want) {
			t.Fatalf("gateway args missing %q:\n%s", want, gw)
		}
	}
	if strings.Contains(gw, "-p ") || strings.Contains(gw, "--publish") || strings.Contains(gw, "--user") {
		t.Fatalf("gateway args expose host ports or user override:\n%s", gw)
	}
	for _, name := range []string{"gateway-flows.mitm", "gateway.log", "gateway-plaintext.txt", "dns.log", "dns-observation.json", "gateway-ca-cert.pem"} {
		if _, err := os.Stat(filepath.Join(r.evidenceDir, name)); err != nil {
			t.Fatalf("missing evidence %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "mitmproxy-ca.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private key copied into evidence: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(r.evidenceDir, "gateway-flows.mitm")); err != nil || string(got) != "FLOWDATA\n" {
		t.Fatalf("gateway-flows.mitm = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(r.evidenceDir, "dns.log")); err != nil || !strings.Contains(string(got), "DNS QUERY") {
		t.Fatalf("dns.log = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(r.evidenceDir, "dns-observation.json")); err != nil || !strings.Contains(string(got), `"renderedQueryLines":1`) {
		t.Fatalf("dns-observation.json = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(state, "stopped-"+r.proxyName)); err != nil {
		t.Fatalf("gateway was not stopped: %v", err)
	}
	raw, err := b.RawRecords(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source, recordType, artifact string
	}{{sourceGatewayFlows, "gateway/flow", "gateway-flows.mitm"}, {sourceGatewayView, "gateway/view", "gateway-plaintext.txt"}, {sourceDNS, "dns/log", "dns.log"}, {sourceDNS, "dns/observation", "dns-observation.json"}} {
		metas := netRecords(t, raw, tc.source, tc.recordType)
		if len(metas) != 1 || metas[0].Artifact != tc.artifact {
			t.Fatalf("%s records = %#v", tc.source, metas)
		}
		content, err := os.ReadFile(filepath.Join(r.evidenceDir, tc.artifact))
		if err != nil {
			t.Fatal(err)
		}
		if backend.SHA256Hex(content) != metas[0].SHA256 || uint64(len(content)) != metas[0].Size {
			t.Fatalf("artifact %s digest mismatch", tc.artifact)
		}
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{sourceGatewayFlows, sourceGatewayView, sourceDNS} {
		src := findSource(t, health, id)
		if !src.Started || !src.Drained || !src.Stopped || src.Drops != 0 {
			t.Fatalf("%s health = %#v", id, src)
		}
	}
	if err := b.Destroy(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "container-"+r.proxyName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("gateway container leaked: %v", err)
	}
	if _, err := os.Stat(r.proxyDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("proxy dir leaked: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "gateway-flows.mitm")); err != nil {
		t.Fatalf("evidence destroyed with proxy dir: %v", err)
	}
}

func TestGatewayUnavailableStillCompletesWorkload(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "fail-gateway"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	runargs, err := os.ReadFile(filepath.Join(state, "runargs-"+r.containerName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runargs), "--dns=") || strings.Contains(string(runargs), "http_proxy") {
		t.Fatalf("workload got gateway env without a ready gateway:\n%s", runargs)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{sourceGatewayFlows, sourceGatewayView, sourceDNS} {
		src := findSource(t, health, id)
		if src.Started || src.Drained || src.Drops < 1 {
			t.Fatalf("%s health = %#v", id, src)
		}
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "gateway-flows.mitm")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected gateway flows artifact: %v", err)
	}
}

func TestGatewayResolverWriteFailureLeavesDNSUnhealthy(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("run-resolver-write-failure"), testPlan(t, "alpine:3.21", "sh", "-c", "true"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if err := os.WriteFile(r.resolverFile, []byte("PRIVATE KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(runArgs(t, state, r.containerName), "\n")
	if strings.Contains(args, "dst=/etc/resolv.conf") || strings.Contains(args, "PRIVATE KEY") {
		t.Fatalf("workload got a failed resolver mount or private material:\n%s", args)
	}
	if !strings.Contains(args, "--env=http_proxy=http://10.88.0.2:8080") {
		t.Fatalf("workload lost usable direct gateway proxy fallback:\n%s", args)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	dns := findSource(t, health, sourceDNS)
	if !dns.Started || dns.Drained || dns.Drops < 1 {
		t.Fatalf("dns health = %#v", dns)
	}
}

func TestGatewayEmptyDNSArtifactIsHealthy(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "empty-gateway-dns"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	content, err := os.ReadFile(filepath.Join(r.evidenceDir, "dns.log"))
	if err != nil || len(content) != 0 {
		t.Fatalf("dns artifact = %q, %v", content, err)
	}
	raw, err := b.RawRecords(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if records := netRecords(t, raw, sourceDNS, "dns/log"); len(records) != 1 || records[0].Artifact != "dns.log" {
		t.Fatalf("dns records = %#v", records)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	dns := findSource(t, health, sourceDNS)
	if !dns.Started || !dns.Drained || dns.Drops != 0 {
		t.Fatalf("dns health = %#v", dns)
	}
	count, err := os.ReadFile(filepath.Join(r.evidenceDir, "dns-observation.json"))
	if err != nil || !strings.Contains(string(count), `"renderedQueryLines":0`) {
		t.Fatalf("dns observation = %q, %v", count, err)
	}
}

func TestGatewayRenderFailureKeepsRawArchive(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "fail-gateway-render"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if _, err := os.Stat(filepath.Join(r.evidenceDir, "gateway-flows.mitm")); err != nil {
		t.Fatalf("raw flow archive not preserved: %v", err)
	}
	for _, name := range []string{"gateway-plaintext.txt", "dns.log"} {
		if _, err := os.Stat(filepath.Join(r.evidenceDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial derived artifact %s retained: %v", name, err)
		}
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	flows := findSource(t, health, sourceGatewayFlows)
	if !flows.Started || !flows.Drained || flows.Drops != 0 {
		t.Fatalf("flows health = %#v", flows)
	}
	for _, id := range []string{sourceGatewayView, sourceDNS} {
		src := findSource(t, health, id)
		if src.Started || src.Drained || src.ParseFailures < 1 {
			t.Fatalf("%s health = %#v", id, src)
		}
	}
}

func TestGatewayBadIPDegradesAndRunsPlain(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "gateway-badip"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if r.gatewayIP != "" {
		t.Fatalf("gatewayIP = %q", r.gatewayIP)
	}
	runargs, err := os.ReadFile(filepath.Join(state, "runargs-"+r.containerName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runargs), "--dns=") {
		t.Fatalf("workload got gateway DNS with invalid IP:\n%s", runargs)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	flows := findSource(t, health, sourceGatewayFlows)
	if flows.Drops < 1 || flows.Drained {
		t.Fatalf("flows health = %#v", flows)
	}
}

func TestGatewayListenerProbeFailureDegradesBeforeWorkload(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "gateway-probe-fails"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, r := runSimpleWorkload(t, state)
	if r.gatewayIP != "" {
		t.Fatalf("gatewayIP = %q", r.gatewayIP)
	}
	runargs, err := os.ReadFile(filepath.Join(state, "runargs-"+r.containerName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runargs), "--env=http_proxy=") {
		t.Fatalf("workload got an unready proxy:\n%s", runargs)
	}
	_, health, err := b.FinalizeEvidence(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{sourceGatewayFlows, sourceGatewayView, sourceDNS} {
		src := findSource(t, health, id)
		if src.Drops == 0 || src.Drained {
			t.Fatalf("%s health = %#v", id, src)
		}
	}
}
