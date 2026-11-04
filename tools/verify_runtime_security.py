#!/usr/bin/env python3
"""Create a runtime SBOM and enforce SAT release security floors.

This is intentionally offline. It does not pretend a cached version floor is a
live vulnerability database. Official packaging also fails when the policy is
stale so dependency review must be refreshed for the release date.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config/security/runtime-security-policy.json"


def parse_version(value: str):
    nums = re.findall(r"\d+", value)
    return tuple(int(x) for x in nums[:4])


def version_at_least(found: str, minimum: str) -> bool:
    a, b = parse_version(found), parse_version(minimum)
    width = max(len(a), len(b))
    return a + (0,) * (width-len(a)) >= b + (0,) * (width-len(b))


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()


def strings(path: Path) -> str:
    try:
        return subprocess.check_output(["strings", str(path)], text=True, errors="replace", stderr=subprocess.DEVNULL)
    except Exception:
        data=path.read_bytes()
        return "\n".join(m.decode('ascii','ignore') for m in re.findall(rb'[ -~]{6,}',data))


def detect_component(path: Path):
    name=path.name.lower()
    text=None
    if 'libcrypto' in name or 'libssl' in name:
        text=strings(path)
        m=re.search(r'OpenSSL\s+(\d+\.\d+\.\d+[a-z0-9.-]*)', text)
        return ('openssl', m.group(1) if m else 'unknown')
    if 'libarchive' in name:
        text=strings(path)
        m=re.search(r'libarchive\s+(\d+\.\d+\.\d+)', text)
        return ('libarchive', m.group(1) if m else 'unknown')
    if 'libssh2' in name:
        text=strings(path)
        m=re.search(r'libssh2[_ /-](\d+\.\d+\.\d+)', text)
        return ('libssh2', m.group(1) if m else 'unknown')
    if 'libsqlite3' in name or name.startswith('sqlite3'):
        text=strings(path)
        # SQLite embeds its source version as a standalone string.
        versions=re.findall(r'(?m)^(3\.\d+\.\d+)$', text)
        return ('sqlite', versions[0] if versions else 'unknown')
    return (None, None)


def load_provenance(stage: Path):
    """What we built from source, and from which commit.

    Written by tools/Build-ThirdParty-Linux.sh when it builds a dependency from source. Absent for
    a package that only bundles distribution libraries, which is fine until the policy names a
    requiredFixCommit for one of them.
    """
    for candidate in (stage/'lib'/'RUNTIME-PROVENANCE.json', stage/'RUNTIME-PROVENANCE.json'):
        if candidate.is_file():
            try:
                data=json.loads(candidate.read_text())
            except Exception as exc:
                return {}, f"provenance record {candidate.name} is unreadable ({exc})"
            comps=data.get('components')
            if not isinstance(comps,dict):
                return {}, f"provenance record {candidate.name} has no components map"
            return comps, None
    return {}, None


def scan_files(stage: Path, platform: str):
    if platform == 'linux':
        base=stage/'lib'
        paths=sorted(p for p in base.glob('*') if p.is_file()) if base.exists() else []
        exe=stage/'SupportAssistTool'
        if exe.is_file(): paths.insert(0,exe)
    else:
        fw=stage/'Contents'/'Frameworks'
        paths=sorted(p for p in fw.glob('*') if p.is_file()) if fw.exists() else []
        exe=stage/'Contents'/'MacOS'/'SupportAssistTool'
        if exe.is_file(): paths.insert(0,exe)
    return paths


def permission_findings(stage: Path, platform: str):
    findings=[]
    if platform != 'linux': return findings
    uid=os.getuid() if hasattr(os,'getuid') else None
    for p in [stage, stage/'lib', stage/'SupportAssistTool']:
        if not p.exists(): continue
        st=p.stat()
        if st.st_mode & 0o022:
            findings.append(f"writable-by-group-or-other: {p}")
        if uid is not None and st.st_uid not in (uid,0):
            findings.append(f"unexpected-owner-uid-{st.st_uid}: {p}")
    for p in (stage/'lib').glob('*') if (stage/'lib').exists() else []:
        if p.is_symlink(): findings.append(f"runtime-library-symlink: {p}")
        if p.stat().st_mode & 0o022: findings.append(f"writable-runtime-library: {p}")
    return findings


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--stage', type=Path, required=True)
    ap.add_argument('--platform', choices=['linux','macos'], required=True)
    ap.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--developer', action='store_true', help='report failures but do not return release-blocking exit code')
    args=ap.parse_args()
    policy=json.loads(args.policy.read_text())
    reviewed=dt.date.fromisoformat(policy['reviewedOn'])
    age=(dt.date.today()-reviewed).days
    stale=age > int(policy.get('maximumPolicyAgeDays',60))
    provenance,provenance_error=load_provenance(args.stage)
    files=scan_files(args.stage,args.platform)
    components=[]; detected={}
    for path in files:
        comp,ver=detect_component(path)
        row={'name':path.name,'path':str(path.relative_to(args.stage)),'sha256':sha256(path),'bytes':path.stat().st_size}
        if comp:
            row['component']=comp; row['version']=ver
            # libssl and libcrypto intentionally collapse to one OpenSSL decision.
            if comp not in detected or detected[comp]=='unknown': detected[comp]=ver
        components.append(row)
    failures=[]
    if stale:
        failures.append(f"security policy is {age} days old (maximum {policy.get('maximumPolicyAgeDays')} days)")
    for key,cfg in policy['components'].items():
        if key not in detected: continue
        found=detected[key]; minimum=cfg['minimumVersion']
        required_series=str(cfg.get('requiredSeries','')).strip()
        if found == 'unknown':
            failures.append(f"{cfg['displayName']} version could not be determined")
            continue
        if required_series and not (found == required_series or found.startswith(required_series + '.')):
            failures.append(f"{cfg['displayName']} {found} is outside approved release series {required_series}.x")
            continue
        if not version_at_least(found,minimum):
            failures.append(f"{cfg['displayName']} {found} is below release floor {minimum}")
            continue
        # A fix that exists only as an upstream commit cannot be expressed as a version. Every
        # master snapshot reports the same in-development version number whether or not it carries
        # the fix, so the package must say which commit it was built from and it must match.
        required_commit=str(cfg.get('requiredFixCommit','')).strip().lower()
        if required_commit:
            if provenance_error:
                failures.append(f"{cfg['displayName']} requires source build provenance: {provenance_error}")
                continue
            record=provenance.get(key) or {}
            built_from=str(record.get('sourceCommit','')).strip().lower()
            if not built_from:
                failures.append(
                    f"{cfg['displayName']} {found} carries no build provenance, and policy requires "
                    f"it to be built from commit {cfg.get('requiredFixCommitShort',required_commit[:8])} "
                    f"({cfg.get('advisory','advisory')})")
            elif built_from != required_commit:
                failures.append(
                    f"{cfg['displayName']} was built from commit {built_from[:12]} but policy "
                    f"requires {required_commit[:12]}")
    perms=permission_findings(args.stage,args.platform)
    failures.extend(perms)
    sbom={
      'bomFormat':'SAT-RUNTIME-SBOM','specVersion':'1.0','generatedUtc':dt.datetime.now(dt.timezone.utc).isoformat(),
      'platform':args.platform,'stage':str(args.stage),'securityPolicy':policy,
      'detectedSecurityComponents':detected,'components':components,'releaseSecurityFindings':failures,
      'sourceBuildProvenance':provenance,
      'releaseSecurityApproved':not failures
    }
    out=args.output or (args.stage/'RUNTIME-SBOM.json')
    out.write_text(json.dumps(sbom,indent=2)+"\n")
    print(f"Runtime security SBOM: {out}")
    for key,ver in sorted(detected.items()): print(f"  {key}: {ver}")
    if failures:
        print("Release security gate: FAIL")
        for f in failures: print(f"  - {f}")
        return 0 if args.developer else 3
    print("Release security gate: PASS")
    return 0

if __name__=='__main__': sys.exit(main())
