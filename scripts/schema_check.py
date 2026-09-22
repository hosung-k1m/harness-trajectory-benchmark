#!/usr/bin/env python3
"""Validate committed Phase 0 fixtures with an independent Draft 2020-12 engine."""
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"


def validator(path):
    schema = json.loads(path.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def check(v, value, expected, label):
    actual = v.is_valid(value)
    if actual != expected:
        errors = [str(e) for e in v.iter_errors(value)]
        raise AssertionError(f"{label}: schema accepted={actual}, expected={expected}: {errors[:2]}")


def main():
    event = validator(SCHEMAS / "tracked-events/tracked-events.v1.schema.json")
    lines = (ROOT / "testdata/golden/tracked-events.v1.jsonl").read_text().splitlines()
    golden = [json.loads(line) for line in lines if line.strip()]
    for i, value in enumerate(golden, 1):
        check(event, value, True, f"golden event {i}")
    for field, bad in [("seq", 0), ("type", ""), ("data", None)]:
        value = copy.deepcopy(golden[0])
        value[field] = bad
        check(event, value, False, f"negative tracked event {field}")

    openai = validator(SCHEMAS / "openai-chat-completions-v1/openai.chat-completions.v1.json")
    for value in golden:
        kind = {"model/request": "request", "model/stream-chunk": "chunk", "model/response": "response"}.get(value["type"])
        if kind:
            body = value["data"]["details"]["body"]
            sub = Draft202012Validator({"$ref": f"#/$defs/{kind}", "$defs": openai.schema["$defs"]})
            check(sub, body, True, f"golden {value['type']} body")
    for state, expected in [("valid", True), ("invalid", False)]:
        for path in sorted((SCHEMAS / "openai-chat-completions-v1/fixtures" / state).glob("*.json")):
            check(openai, json.loads(path.read_text()), expected, str(path.relative_to(ROOT)))

    raw = validator(SCHEMAS / "evidence/raw-record.v1.schema.json")
    digest = "a" * 64
    record = {"runId": "run", "sensorId": "sensor", "bootId": "boot", "sourceSeq": 1,
              "recordType": "test", "encoding": "binary", "payload": "cGF5bG9hZA==",
              "previousRecordSha256": "", "recordSha256": "0431ce86610432c4bcf96f2a4f3b53f5e2378771cf138a6281922727b8e2975b"}
    check(raw, record, True, "raw record")
    bad = dict(record, sourceSeq=0)
    check(raw, bad, False, "raw record sequence")
    bad = dict(record, recordSha256="bad")
    check(raw, bad, False, "raw record digest")

    manifest_schema = validator(SCHEMAS / "evidence/run-evidence-manifest.v1.schema.json")
    manifest = {"schemaVersion": "v1", "runId": "run", "runSpecDigest": digest,
                "observationPlanDigest": digest, "capabilityManifestDigest": digest,
                "sensorHealthDigest": digest, "trackedEventChainHead": digest,
                "rawChainHeads": {}, "artifacts": [], "merkleRoot": digest,
                "sealedAt": "2026-01-01T00:00:00Z"}
    check(manifest_schema, manifest, True, "manifest")
    check(manifest_schema, dict(manifest, merkleRoot="bad"), False, "manifest digest")

    bundle_schema = validator(SCHEMAS / "evidence/bundle.v1.schema.json")
    bundle_doc = {"schemaVersion": "htb.evidence-bundle.v1", "runId": "run-1",
                  "manifest": {}, "files": {"tracked-events.jsonl": "", "workload/raw-records.bin": "AA=="}}
    check(bundle_schema, bundle_doc, True, "bundle")
    check(bundle_schema, dict(bundle_doc, schemaVersion="v2"), False, "bundle version")
    check(bundle_schema, dict(bundle_doc, files={"x": 1}), False, "bundle file encoding")
    check(bundle_schema, dict(bundle_doc, extra=1), False, "bundle additional properties")

    api = validator(SCHEMAS / "control-api/v1.json")
    spec = {"schemaVersion": "v1", "harness": "h", "suite": "s", "backend": "b"}
    for name, valid, invalid in [
        ("createRunRequest", {"spec": spec}, {"spec": dict(spec, schemaVersion="v2")}),
        ("lifecycleMutation", {"action": "start"}, {"action": "restart"}),
        ("run", {"id": "run-1", "spec": spec, "status": "created", "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z"}, {"id": "bad id", "spec": spec, "status": "created", "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z"}),
        ("trackedEvent", golden[0], dict(golden[0], seq=0)),
        ("verificationResult", {"status": "ineligible", "eligible": False}, {"status": "ineligible"}),
        ("evidenceReport", {"runId": "run", "status": "ineligible"}, {"runId": "run"}),
        ("capabilityManifest", {"backend": "b", "version": "1", "schemaVersion": "v1", "capabilities": []}, {"backend": "b"}),
        ("compatibility", {"apiVersions": ["v1"], "schemas": [], "streamingFormats": ["jsonl"]}, {"apiVersions": ["v1"]}),
        ("apiError", {"code": "invalid", "message": "bad"}, {"code": "invalid"}),
        ("runPage", {"items": []}, {"items": "bad"}),
        ("trajectoryPage", {"items": golden[:1]}, {"items": [dict(golden[0], seq=0)]}),
    ]:
        subschema = {"$ref": f"#/$defs/{name}", "$defs": api.schema["$defs"]}
        sub = Draft202012Validator(subschema, format_checker=FormatChecker())
        check(sub, valid, True, f"control {name} valid")
        check(sub, invalid, False, f"control {name} invalid")
    print(f"Phase 0 schemas: {len(golden)} golden events, 10 OpenAI fixtures, evidence and 11 control API definitions passed")


if __name__ == "__main__":
    main()
