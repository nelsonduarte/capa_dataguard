#!/bin/sh
# Regenerate the DataGuard machine-verifiable artefacts:
#
#   out/report.txt          the public analytics report
#   out/attestation.txt     the human-readable non-leak attestation
#   out/attestation.json    the machine-readable attestation
#   sbom/manifest.json      the capability manifest (declassify sites + surface)
#   sbom/sbom.cyclonedx.json  CycloneDX 1.5 SBOM with the manifest embedded
#   sbom/sbom.spdx.json       SPDX 2.3 SBOM companion
#   sbom/provenance.slsa.json SLSA build provenance
#
# The report and attestation are produced by RUNNING DataGuard; the SBOM
# family is EMITTED BY THE COMPILER from the same source. Together they
# are the attestation: the program states the claim, the compiler proves
# it (information-flow analysis + the capability surface in the SBOM).
#
# Determinism comes from SOURCE_DATE_EPOCH (reproducible-builds.org): the
# compiler stamps the SBOM build time from this fixed instant, so the
# artefacts are byte-reproducible. Bump it by writing a new UTC epoch to
# sbom/SOURCE_DATE_EPOCH and rerunning this script.
#
# Run all Capa invocations through the LOCAL compiler:
#     python -m capa ...   (from a checkout of the Capa compiler on PATH)
# The examples below assume `capa` resolves to that build.
set -e

SOURCE_DATE_EPOCH="$(tr -d '\r' < sbom/SOURCE_DATE_EPOCH)"
export SOURCE_DATE_EPOCH

mkdir -p out sbom

# Run the pipeline (Python backend) to produce the report + attestation.
capa --run dataguard.capa

# Emit the compiler-side proof artefacts.
capa --manifest   dataguard.capa > sbom/manifest.json
capa --cyclonedx  dataguard.capa > sbom/sbom.cyclonedx.json
capa --spdx       dataguard.capa > sbom/sbom.spdx.json
capa --provenance dataguard.capa > sbom/provenance.slsa.json

echo "regenerated out/ and sbom/ (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
