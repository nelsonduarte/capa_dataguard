# DataGuard

A data-governance pipeline that **proves, by construction, that personal
data cannot leak to an unauthorised output**. The proof is not a policy
document or a code review sign-off. It is the output of a compiler: the
[Capa](https://github.com/nelsonduarte) information-flow analysis rejects
any path from a personal-data field to a public sink, and the capability
SBOM Capa emits for this program enumerates exactly where, and why, the
one sanctioned disclosure happens and what authority the program holds.

## The problem

Every organisation that processes customer records has the same
obligation and the same risk. Under GDPR (Art. 5, 25, 32) and CCPA, a
processor must show that personal data (name, email, national id, bank
account) does not end up somewhere it should not: an analytics export, a
log file, a third-party feed. Today that assurance is built from process:
data-flow diagrams, DPIAs, code reviews, DLP scanners that pattern-match
after the fact. None of it is a *proof*. A single refactor can route an
email into a public report, and nothing in the build fails.

DataGuard shows a different model. The guarantee "no raw personal data
reaches the public report" is a **compile-time invariant**. If a developer
writes the leak, the build stops. The evidence that the shipped build
upholds it is a machine-readable artefact an auditor can re-verify.

## What DataGuard does

It is a realistic customer-record processor. Given a dataset of customer
records, it:

1. **Parses and validates** the input (RFC 4180 CSV, via the pure
   `capa_csv` library), turning each row into a typed `Record`.
2. **Aggregates public metrics** (counts, sums, averages) by region,
   plan and signup month, derived *only* from the non-personal fields.
3. **Pseudonymises** each subject: a keyed, non-reversible HMAC-SHA256
   token of the email (via the pure `capa_hash` library), exposed through
   a single **audited `declassify`** with a recorded GDPR reason.
4. **Routes outputs** to distinct destinations under least privilege:
   a **public analytics report** (`out/report.txt`, metrics plus
   pseudonymised subjects) written through a write-only, `out/`-scoped
   filesystem view; a run log on the console. Raw personal data can reach
   neither, and the compiler is what guarantees it.
5. **Attests** the run: a text and a JSON attestation (`out/attestation.*`)
   declaring how many records were processed, which fields were personal
   data held under a confidentiality label, the single disclosure bridge,
   and the non-leak claim, pointing at the compiler artefacts that back it.

### The data model is the policy

```capa
pub type Record {
    name: @secret String,          // personal data - never in the clear
    email: @secret String,         // pseudonymised only, never raw
    national_id: @secret String,   // never disclosed
    iban: @secret String,          // never disclosed
    region: String,                // non-personal, analytic
    plan: String,                  // non-personal, analytic
    signup_date: String,           // non-personal, analytic
    amount_cents: Int              // non-personal, analytic
}
```

The four `@secret` annotations are the entire confidentiality policy.
From them the compiler propagates a security label through every derived
value and proves it cannot reach a public sink (a report file, the
console) without crossing a `declassify`. There is nothing else to trust:
no runtime monitor, no scanner, no reviewer's diligence.

## Why the non-leak guarantee is machine-verifiable

Two independent, compiler-enforced properties, plus the artefacts that
record them.

### 1. Information-flow control: the leak does not compile

A `@secret` value that reaches a public sink without an audited
`declassify` is a compile-time error. `leaky_dataguard.capa` is the
counter-example that makes this concrete: it deliberately tries to write
raw personal data to the report and the console, and the compiler refuses
it:

```
$ python -m capa --check leaky_dataguard.capa
leaky_dataguard.capa:30:38: error: information-flow: a @secret value reaches
  Fs.write (argument 2), a public sink that sends data out of the program.
  Route it through declassify(value, reason: "...") if this disclosure is intended.
leaky_dataguard.capa:38:19: error: information-flow: a @secret value reaches
  Stdio.println (argument 1), a public sink ...
leaky_dataguard.capa:44:38: error: information-flow: a @secret value reaches
  Fs.write (argument 2), a public sink ...
leaky_dataguard.capa: 3 errors            # exit code 1
```

The real pipeline (`dataguard.capa`) checks clean. The single legitimate
secret-to-public crossing is the pseudonym token, made explicit at one
`declassify` with a GDPR reason:

```capa
pub fun subject_token(r: Record) -> String
    let full = hmac_sha256_hex_utf8(pseudonym_key(), r.email)
    return declassify(
        "subj_${full.substring(0, 16)}",
        reason: "GDPR Art. 4(5) pseudonymisation: the public report references a
                 subject only by a keyed one-way token of the email, from which
                 the email cannot be recovered; the direct identifier never
                 leaves the secret domain"
    )
```

### 2. Capability discipline: the pipeline provably cannot exfiltrate

`main` acquires exactly two capabilities, `Fs` and `Stdio`, and
immediately splits the filesystem authority into a **read-only view over
`data/`** and a **write view over `out/`**. It never acquires `Net`,
`Env`, `Proc`, `Db`, `Clock`, `Random` or `Unsafe`. The compiler proves
it, and the SBOM records it:

```
$ python -m capa --manifest dataguard.capa \
    | jq '.functions[] | select(.source_name=="main")
          | {declared: .declared_capabilities, excluded: .provably_excluded_capabilities}'
{
  "declared": ["Stdio", "Fs"],
  "excluded": ["Clock", "Db", "Env", "Net", "Proc", "Random", "Unsafe"]
}
```

"This pipeline cannot phone home" is therefore a checked fact, not a
promise: with no `Net` capability anywhere in the program, there is no
code path that reaches the network.

### 3. The artefacts: attestation + SBOM

`./generate.sh` produces, byte-reproducibly (pinned `SOURCE_DATE_EPOCH`):

| Artefact | Emitted by | What it proves |
| --- | --- | --- |
| `out/report.txt` | running DataGuard | the public output carries only metrics + pseudonyms |
| `out/attestation.txt` / `.json` | running DataGuard | the non-leak claim, in prose and machine-readable form |
| `sbom/manifest.json` | `capa --manifest` | 1 declassification site (the pseudonym bridge) + the capability surface |
| `sbom/sbom.cyclonedx.json` | `capa --cyclonedx` | CycloneDX 1.5 SBOM (Dependency-Track, OSV-Scanner, syft) |
| `sbom/sbom.spdx.json` | `capa --spdx` | SPDX 2.3 companion (OpenChain pipelines) |
| `sbom/provenance.slsa.json` | `capa --provenance` | SLSA build provenance over the source |

The manifest names the one disclosure with its reason:

```
$ python -m capa --manifest dataguard.capa | jq '.summary.declassification_sites'
1
```

One site, not zero (the pseudonym must cross), not many. The attestation
is the program's claim; the SBOM is the compiler's evidence. Together
they are the machine-verifiable non-leak attestation.

## Layout

| Path | Role |
| --- | --- |
| `domain.capa` | the typed data model; the `@secret` annotations that are the policy |
| `ingest.capa` | CSV parse + validation into `Record`s (pure) |
| `metrics.capa` | public aggregation from non-personal fields (pure) |
| `pseudonym.capa` | the single audited `declassify` bridge (HMAC pseudonym) |
| `report.capa` | build the public report string (pure) |
| `attest.capa` | build the text + JSON attestation (pure) |
| `dataguard.capa` | the orchestrator: read (Fs ro) -> pipeline -> write (Fs wo) |
| `leaky_dataguard.capa` | counter-example: the leak the compiler rejects |
| `data/customers.csv` | sample dataset (14 records, fictitious PII) |
| `out/` | sample generated report + attestation |
| `sbom/` | sample generated manifest + SBOMs + provenance |
| `vendor/capa_csv`, `vendor/capa_hash` | pure, capability-free path dependencies |

## Run it

All commands use the local Capa compiler; substitute `python -m capa` for
`capa` if the installed `capa` is not the build you intend.

```sh
# Type-check + information-flow check (clean: no leaks)
capa --check dataguard.capa

# Run the pipeline. Writes out/report.txt and out/attestation.{txt,json}.
capa --run dataguard.capa

# See the information-flow checker reject a deliberate personal-data leak
capa --check leaky_dataguard.capa        # 3 errors, exit code 1

# Regenerate the report, attestation and the full SBOM family
./generate.sh
```

### Same source, other backends

DataGuard runs unchanged on the Wasm backend and as a stock WASI
Preview 2 component. The report and attestation are byte-identical
between the Python and Wasm backends (the WASI component differs only in
newline style: LF vs the platform newline).

```sh
capa --wasm --run dataguard.capa                        # identical output
capa --wasm --component --run dataguard.capa            # as a Wasm component
capa --wasm --component --wasi --run dataguard.capa     # stock WASI Preview 2
```

The WASI run needs **no `--preopen`**: every filesystem path in the
program is a string literal at its `Fs` sink (`"data/customers.csv"`,
`"out/report.txt"`, ...), which the compiler resolves by constant
propagation, so the component's filesystem authority is fixed at compile
time rather than granted by the operator. To grant authority explicitly
instead (the operator-declared WASI `--dir` model), pass the directory:

```sh
capa --wasm --component --wasi --preopen out/:rw --run dataguard.capa
```

## Dependencies

Two dependencies, both **pure and capability-free**, vendored under
`vendor/` and wired as **path dependencies** in `capa.toml`:

- `capa_csv` - RFC 4180 CSV parsing (the input reader).
- `capa_hash` - HMAC-SHA256, for the non-reversible pseudonym.

Neither holds any authority, so the DataGuard capability surface stays
exactly `{Fs, Stdio}`. The SBOM proves the dependencies do not widen it.

## Beyond v1 (documented, not shipped)

An external upload of the public report to an allow-listed host via an
attenuated `Net` capability is a natural v2 extension: DataGuard would
then prove, with the same machinery, that the upload path carries no raw
personal data and can reach only the one allowed host. It is left out of
v1 to keep the capability surface at `{Fs, Stdio}` and the story focused
on the in-process non-leak guarantee.

## Licence

MIT. See `LICENSE`. The sample dataset is entirely fictitious.
