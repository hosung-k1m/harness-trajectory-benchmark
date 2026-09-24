package controlplane_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/backend/compat"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/backend/gvisor"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/bundle"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/controlplane"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
)

const fakeSudoScript = `#!/bin/sh
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
              *dumper_filter*) printf '172.18.0.3:42152: DNS QUERY (A) probe.invalid\n << NXDOMAIN\n';;
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
	if err := os.WriteFile(bin, []byte(fakeSudoScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DOCKER_STATE", state)
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	return state
}

func gvisorConfig(t *testing.T) json.RawMessage {
	t.Helper()
	config, err := json.Marshal(map[string]any{"type": "gvisor/container-v1", "image": "alpine:3.21", "command": []string{"sh", "-c", "true"}})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func newDispatchClient(t *testing.T, dataDir string, key ed25519.PrivateKey) (*client.Client, *api.Store, *controlplane.DispatchDriver, *controlplane.CompatDriver) {
	t.Helper()
	compatDriver := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: filepath.Join(dataDir, "workloads")}))
	if err := compatDriver.ConfigureManifest(dataDir, key); err != nil {
		t.Fatal(err)
	}
	gvisorDriver := controlplane.NewGvisorDriver(gvisor.New(gvisor.Config{RootDir: filepath.Join(dataDir, "gvisor-runs")}))
	if err := gvisorDriver.ConfigureManifest(dataDir, key); err != nil {
		t.Fatal(err)
	}
	dispatch := controlplane.NewDispatchDriver(map[string]api.RunDriver{
		"compat-local-process": compatDriver,
		"gvisor-container":     gvisorDriver,
	})
	factory := func(run api.Run) (api.EventLog, error) {
		return appender.Open(filepath.Join(dataDir, "runs", run.ID, "tracked-events.jsonl"))
	}
	store, err := api.OpenStore(dataDir, factory, dispatch)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatch.BindStore(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	t.Cleanup(server.Close)
	return client.New(server.URL), store, dispatch, compatDriver
}

func createGvisorRun(t *testing.T, c *client.Client, verified bool) client.Run {
	t.Helper()
	run, err := c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "gvisor-container", Verified: verified, Parameters: map[string]json.RawMessage{"backendConfig": gvisorConfig(t)}}})
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func decodeExportedBundle(t *testing.T, c *client.Client, runID string) bundle.Bundle {
	t.Helper()
	exported, err := c.ExportEvidence(context.Background(), runID)
	if err != nil || len(exported) == 0 {
		t.Fatalf("export: %v", err)
	}
	decoded, err := bundle.Decode(bytes.NewReader(exported))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestGvisorDriverHTTPSlicePublishesRawOnlyBundle(t *testing.T) {
	state := installFakeSudo(t)
	runscDir := t.TempDir()
	t.Setenv("FAKE_RUNSC_DIR", runscDir)
	t.Setenv("FAKE_SECCHECK_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		if err := dispatch.Close(); err != nil {
			t.Error(err)
		}
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()

	run := createGvisorRun(t, c, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("status=%q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	if report.Verification == nil || report.Verification.Status != "ineligible" || report.Verification.Eligible {
		t.Fatalf("evidence report = %#v verification = %+v", report, report.Verification)
	}
	allEvents, err := c.Events(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(allEvents) != 2 || allEvents[0].Type != "run/start" || allEvents[1].Type != "run/finish" {
		t.Fatalf("trajectory contains normalized events: %#v", allEvents)
	}
	if report.Verification.EventCount != uint64(len(allEvents)) || report.Verification.TrackedEventChainHead == "" {
		t.Fatalf("verification = %#v", report.Verification)
	}
	decoded := decodeExportedBundle(t, c, run.ID)
	result, err := bundle.Validate(decoded, publicKey)
	if err != nil {
		t.Fatalf("bundle validate: %v", err)
	}
	if !result.IntegrityValid || result.Eligible || result.RunID != run.ID {
		t.Fatalf("bundle result = %#v", result)
	}
	for _, name := range []string{"api-run-spec.json", "run-spec.json", "observation-plan.json", "capability-manifest.json", "sensor-health.json", "raw-records.json", "verification.json", "tracked-events.jsonl", "tracked-events.jsonl.sealed", "workload/raw-records.bin", "workload/stdout.log", "workload/stderr.log", "workload/workspace-before.tar", "workload/workspace-after.tar"} {
		if _, ok := decoded.Files[name]; !ok {
			t.Fatalf("bundle missing %q", name)
		}
	}
	var runscFiles int
	for name := range decoded.Files {
		if strings.HasPrefix(name, "workload/runsc.facefeed") {
			runscFiles++
		}
	}
	if runscFiles != 2 {
		t.Fatalf("runsc artifacts = %d", runscFiles)
	}
	if _, ok := decoded.Files["workload/seccheck.frames"]; !ok {
		t.Fatal("bundle missing seccheck.frames")
	}
	if got := string(decoded.Files["workload/seccheck.done"]); got != "{\"frames\":2,\"oversize\":0,\"reportedDrops\":0}\n" {
		t.Fatalf("seccheck.done = %q", got)
	}
	for _, name := range []string{"workload/bridge-ingress.pcap", "workload/bridge-egress.pcap", "workload/veth-ingress.pcap", "workload/veth-egress.pcap", "workload/net-inspect-start.json", "workload/net-inspect-stop.json", "workload/iptables-start.txt", "workload/iptables-stop.txt", "workload/nft-start.txt", "workload/nft-stop.txt", "workload/gateway-flows.mitm", "workload/gateway.log", "workload/gateway-plaintext.txt", "workload/dns.log", "workload/gateway-ca-cert.pem"} {
		if _, ok := decoded.Files[name]; !ok {
			t.Fatalf("bundle missing %s", name)
		}
	}
	for name := range decoded.Files {
		if strings.Contains(name, "mitmproxy-ca.pem") || strings.Contains(name, "mitmproxy-ca.p12") {
			t.Fatalf("private gateway key material in bundle: %s", name)
		}
	}
	var health backend.SensorHealth
	if err := json.Unmarshal(decoded.Files["sensor-health.json"], &health); err != nil {
		t.Fatal(err)
	}
	if len(health.Sources) != 14 {
		t.Fatalf("health sources = %#v", health.Sources)
	}
	runs, err := filepath.Glob(filepath.Join(dataDir, "gvisor-runs", run.ID+"-*"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("gvisor run dirs = %v, %v", runs, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		containers, _ := filepath.Glob(filepath.Join(state, "container-*"))
		networks, _ := filepath.Glob(filepath.Join(state, "network-*"))
		_, wsErr := os.Stat(filepath.Join(runs[0], "workspace"))
		if len(containers) == 0 && len(networks) == 0 && errors.Is(wsErr, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backend resources leaked: containers=%v networks=%v workspaceErr=%v", containers, networks, wsErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "evidence", "raw-records.bin")); err != nil {
		t.Fatalf("evidence not retained: %v", err)
	}
}

func TestGvisorDriverDegradedCollectorStillCompletes(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", filepath.Join(t.TempDir(), "absent"))
	for _, marker := range []string{"fail-logs", "autoexit"} {
		if err := os.WriteFile(filepath.Join(state, marker), []byte("0"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = dispatch.Close()
		_ = store.Close()
	}()
	run := createGvisorRun(t, c, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("status=%q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	if report.Verification == nil || report.Verification.Status != "ineligible" {
		t.Fatalf("evidence report = %#v", report)
	}
	decoded := decodeExportedBundle(t, c, run.ID)
	if _, err := bundle.Validate(decoded, publicKey); err != nil {
		t.Fatalf("bundle validate with degraded collector: %v", err)
	}
	var health backend.SensorHealth
	if err := json.Unmarshal(decoded.Files["sensor-health.json"], &health); err != nil {
		t.Fatal(err)
	}
	var stdout *backend.SensorSourceHealth
	for i := range health.Sources {
		if health.Sources[i].SensorID == "workload/stdout" {
			stdout = &health.Sources[i]
		}
	}
	if stdout == nil || stdout.Drops != 1 || stdout.Started {
		t.Fatalf("stdout source health = %#v", stdout)
	}
}

func TestGvisorDriverDispatchRejects(t *testing.T) {
	installFakeSudo(t)
	dataDir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = dispatch.Close()
		_ = store.Close()
	}()
	_, err = c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "unknown-backend", Parameters: map[string]json.RawMessage{"backendConfig": gvisorConfig(t)}}})
	apiErr, ok := err.(*client.APIError)
	if !ok || apiErr.Code != "execution" || !strings.Contains(apiErr.Message, "unknown backend") {
		t.Fatalf("unknown backend error = %v", err)
	}
	_, err = c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "gvisor-container", Verified: true, Parameters: map[string]json.RawMessage{"backendConfig": gvisorConfig(t)}}})
	if apiErr, ok = err.(*client.APIError); !ok || apiErr.Code != "execution" {
		t.Fatalf("verified gvisor run error = %v", err)
	}
	_, err = c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "gvisor-container"}})
	if apiErr, ok = err.(*client.APIError); !ok || apiErr.Code != "execution" {
		t.Fatalf("missing backendConfig error = %v", err)
	}
}

func TestGvisorDriverStopSealsAndPublishes(t *testing.T) {
	installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = dispatch.Close()
		_ = store.Close()
	}()
	run := createGvisorRun(t, c, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "stop", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if got := waitTerminal(t, c, run.ID); got.Status != "stopped" {
		t.Fatalf("status=%q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	if report.Verification == nil || report.Verification.Status != "ineligible" || report.Verification.EventCount != 2 {
		t.Fatalf("evidence report = %#v", report)
	}
	allEvents, err := c.Events(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finish := count(allEvents, "run/finish"); finish != 1 {
		t.Fatalf("run/finish count=%d", finish)
	}
	decoded := decodeExportedBundle(t, c, run.ID)
	if _, err := bundle.Validate(decoded, publicKey); err != nil {
		t.Fatalf("bundle validate: %v", err)
	}
}

func TestGvisorDriverBundleRejectsTamperedArtifact(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = dispatch.Close()
		_ = store.Close()
	}()
	run := createGvisorRun(t, c, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	waitTerminal(t, c, run.ID)
	waitEvidence(t, c, run.ID)
	decoded := decodeExportedBundle(t, c, run.ID)
	if _, err := bundle.Validate(decoded, publicKey); err != nil {
		t.Fatalf("bundle validate: %v", err)
	}
	tampered := decoded.Files["workload/stdout.log"]
	if len(tampered) == 0 {
		t.Fatal("stdout.log artifact is empty")
	}
	tampered[0] ^= 0xff
	if _, err := bundle.Validate(decoded, publicKey); err == nil {
		t.Fatal("tampered artifact validated")
	}
	decoded.Files["workload/stdout.log"] = tampered[:len(tampered)-1]
	delete(decoded.Files, "tracked-events.jsonl.sealed")
	if _, err := bundle.Validate(decoded, publicKey); err == nil {
		t.Fatal("bundle missing a required file validated")
	}
}

func TestGvisorDriverRestartValidatesPersistedBundle(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	run := createGvisorRun(t, c, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	waitTerminal(t, c, run.ID)
	waitEvidence(t, c, run.ID)
	if err := dispatch.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, restored, restartedDispatch, restartedCompat := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = restartedDispatch.Close()
		_ = restored.Close()
	}()
	if err := restartedCompat.ValidatePersistedBundles(); err != nil {
		t.Fatalf("persisted gvisor bundle validation: %v", err)
	}
	report, ok := restored.Evidence(run.ID)
	if !ok || report.Verification == nil || report.Verification.Status != "ineligible" {
		t.Fatalf("restored evidence = %#v", report)
	}
}

func TestGvisorDriverFinalizationFailureRetainsWorkloadStatus(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = dispatch.Close()
		_ = store.Close()
	}()
	run := createGvisorRun(t, c, false)
	runs, err := filepath.Glob(filepath.Join(dataDir, "gvisor-runs", run.ID+"-*"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("gvisor run dirs = %v, %v", runs, err)
	}
	evidenceDir := filepath.Join(runs[0], "evidence")
	if err := os.Chmod(evidenceDir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(evidenceDir, 0o700) }()
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("workload status changed by collector failure: %q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	if report.Verification == nil || report.Verification.Status != "verification_error" {
		t.Fatalf("evidence report = %#v", report)
	}
}

func TestGvisorDriverShutdownRetriesFailedDestroy(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	for _, marker := range []string{"fail-rm", "autoexit"} {
		if err := os.WriteFile(filepath.Join(state, marker), []byte("0"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dataDir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() { _ = store.Close() }()
	run := createGvisorRun(t, c, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("status=%q", got.Status)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		report, err := c.Evidence(context.Background(), run.ID)
		if err == nil && report.Verification != nil && report.Verification.Status == "verification_error" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed destroy did not surface as verification_error")
		}
		time.Sleep(10 * time.Millisecond)
	}
	containers, _ := filepath.Glob(filepath.Join(state, "container-*"))
	if len(containers) != 2 {
		t.Fatalf("expected leaked container markers, got %v", containers)
	}
	if err := os.Remove(filepath.Join(state, "fail-rm")); err != nil {
		t.Fatal(err)
	}
	if err := dispatch.Close(); err != nil {
		t.Fatalf("shutdown retry: %v", err)
	}
	if containers, _ := filepath.Glob(filepath.Join(state, "container-*")); len(containers) != 0 {
		t.Fatalf("container marker survived shutdown retry: %v", containers)
	}
	if networks, _ := filepath.Glob(filepath.Join(state, "network-*")); len(networks) != 0 {
		t.Fatalf("network marker survived shutdown retry: %v", networks)
	}
	runs, _ := filepath.Glob(filepath.Join(dataDir, "gvisor-runs", run.ID+"-*"))
	if len(runs) != 1 {
		t.Fatalf("gvisor run dirs = %v", runs)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "workspace")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace not destroyed: %v", err)
	}
}

func TestGvisorDriverStartFailureDestroysResources(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "fail-run"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = dispatch.Close()
		_ = store.Close()
	}()
	run := createGvisorRun(t, c, false)
	_, err = c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"})
	apiErr, ok := err.(*client.APIError)
	if !ok || apiErr.Code != "execution" {
		t.Fatalf("start error = %v", err)
	}
	if containers, _ := filepath.Glob(filepath.Join(state, "container-*")); len(containers) != 0 {
		t.Fatalf("container marker leaked: %v", containers)
	}
	if networks, _ := filepath.Glob(filepath.Join(state, "network-*")); len(networks) != 0 {
		t.Fatalf("network marker leaked: %v", networks)
	}
	runs, _ := filepath.Glob(filepath.Join(dataDir, "gvisor-runs", run.ID+"-*"))
	if len(runs) != 1 {
		t.Fatalf("gvisor run dirs = %v", runs)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "workspace")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace not destroyed after failed start: %v", err)
	}
}

func TestGvisorDriverDegradedSeccheckPartialBundle(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	t.Setenv("FAKE_SECCHECK_DIR", t.TempDir())
	if err := os.WriteFile(filepath.Join(state, "autoexit"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "seccheck-frames"), []byte("\x00\x00\x00\x04ABCD\x00\x00\x00\x0aXY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "seccheck-status"), []byte("{\"frames\":1,\"oversize\":0,\"reportedDrops\":0}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = dispatch.Close()
		_ = store.Close()
	}()

	run := createGvisorRun(t, c, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("status=%q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	if report.Verification == nil || report.Verification.Status != "ineligible" || report.Verification.Eligible {
		t.Fatalf("evidence report = %#v verification = %+v", report, report.Verification)
	}
	decoded := decodeExportedBundle(t, c, run.ID)
	if _, err := bundle.Validate(decoded, publicKey); err != nil {
		t.Fatalf("degraded bundle failed validation: %v", err)
	}
	if _, ok := decoded.Files["workload/seccheck.frames"]; ok {
		t.Fatal("canonical seccheck.frames published despite truncation")
	}
	if _, ok := decoded.Files["workload/seccheck.done"]; ok {
		t.Fatal("canonical seccheck.done published despite truncation")
	}
	partial, ok := decoded.Files["workload/seccheck.partial"]
	if !ok || string(partial) != "\x00\x00\x00\x04ABCD\x00\x00\x00\x0aXY" {
		t.Fatalf("seccheck.partial = %q present=%v", partial, ok)
	}
	if _, ok := decoded.Files["workload/seccheck.partial-status"]; !ok {
		t.Fatal("bundle missing seccheck.partial-status")
	}
	var health backend.SensorHealth
	if err := json.Unmarshal(decoded.Files["sensor-health.json"], &health); err != nil {
		t.Fatal(err)
	}
	var sec *backend.SensorSourceHealth
	for i := range health.Sources {
		if health.Sources[i].SensorID == "seccheck/remote" {
			sec = &health.Sources[i]
		}
	}
	if sec == nil || !sec.Started || sec.Drained || sec.Stopped || sec.ParseFailures < 1 {
		t.Fatalf("seccheck health = %#v", sec)
	}
	var records []struct {
		SensorID   string `json:"sensorId"`
		RecordType string `json:"recordType"`
	}
	if err := json.Unmarshal(decoded.Files["raw-records.json"], &records); err != nil {
		t.Fatal(err)
	}
	frames := 0
	for _, record := range records {
		if record.SensorID == "seccheck/remote" && record.RecordType == "seccheck/frame" {
			frames++
		}
	}
	if frames != 1 {
		t.Fatalf("seccheck frame records = %d", frames)
	}
}

func TestGvisorDriverShutdownSealsBundleBeforeDestroy(t *testing.T) {
	state := installFakeSudo(t)
	t.Setenv("FAKE_RUNSC_DIR", t.TempDir())
	t.Setenv("FAKE_SECCHECK_DIR", t.TempDir())
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, store, dispatch, _ := newDispatchClient(t, dataDir, privateKey)
	defer func() {
		_ = dispatch.Close()
		_ = store.Close()
	}()

	run := createGvisorRun(t, c, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if err := dispatch.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	bundleBytes, err := os.ReadFile(filepath.Join(dataDir, "runs", run.ID, "evidence-bundle.json"))
	if err != nil {
		t.Fatalf("sealed bundle missing after shutdown: %v", err)
	}
	decoded, err := bundle.Decode(bytes.NewReader(bundleBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Validate(decoded, publicKey); err != nil {
		t.Fatalf("shutdown bundle failed validation: %v", err)
	}
	var events []struct {
		Type string `json:"type"`
	}
	for _, line := range bytes.Split(bytes.TrimSpace(decoded.Files["tracked-events.jsonl"]), []byte("\n")) {
		var event struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 2 || events[0].Type != "run/start" || events[1].Type != "run/finish" {
		t.Fatalf("trajectory events = %#v", events)
	}
	if containers, _ := filepath.Glob(filepath.Join(state, "container-*")); len(containers) != 0 {
		t.Fatalf("container marker survived shutdown: %v", containers)
	}
	if networks, _ := filepath.Glob(filepath.Join(state, "network-*")); len(networks) != 0 {
		t.Fatalf("network marker survived shutdown: %v", networks)
	}
	runs, _ := filepath.Glob(filepath.Join(dataDir, "gvisor-runs", run.ID+"-*"))
	if len(runs) != 1 {
		t.Fatalf("gvisor run dirs = %v", runs)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "workspace")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace not destroyed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "evidence", "raw-records.bin")); err != nil {
		t.Fatalf("evidence not retained: %v", err)
	}
	if err := dispatch.Shutdown(context.Background()); err != nil {
		t.Fatalf("repeated shutdown: %v", err)
	}
}
