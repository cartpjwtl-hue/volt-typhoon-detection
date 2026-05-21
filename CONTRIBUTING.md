# Contributing

Thanks for considering a contribution. This repo aims to be an honest, useful, defender-friendly detection pack — not a marketing piece.

## What we accept

- **New detections** that close documented coverage gaps (see the `Roadmap` in README)
- **Tuning improvements** for queries that produce too many false positives
- **TTP corrections** based on new public intelligence (cite the source)
- **Sigma rule conversions** of existing KQL detections
- **Sentinel analytics rule YAMLs** wrapping the queries with entity mappings
- **Documentation improvements** that make the pack easier to deploy

## What we do not accept

- Untested queries without a clear data-source assumption
- Detections lifted from vendor blog posts without attribution
- Changes that overstate coverage (we score honestly — partial means partial)
- Anything that violates the MIT license terms of upstream sources

## Query contribution checklist

When submitting a new detection, include in the file header:

```kql
// Title: <one-line description>
// MITRE: <T-IDs with sub-techniques>
// Data sources: <DeviceProcessEvents | CommonSecurityLog | etc>
// False positive notes: <known FP sources>
// Tested against: <data you validated against, if any>
// Author: <handle or "anonymous">
// Date: <YYYY-MM-DD>
```

## TTP correction checklist

If you're updating a TTP because Volt Typhoon's tradecraft has evolved:

1. Cite the public source (CISA advisory, vendor research blog, etc.)
2. Update both the KQL query and the relevant MITRE layer entry
3. Update the README coverage table if scores shift
4. Note the change in `CHANGELOG.md` with the date

## Pull request flow

1. Fork the repo and create a feature branch
2. Make your changes — keep PRs focused (one detection or one fix per PR)
3. Update relevant docs and the MITRE layer if scores change
4. Open a PR with a clear description of what changed and why
5. Address review comments

## Code of conduct

Be honest, be technical, be kind. No bashing of vendors, security teams, or other contributors.

## Questions?

Open an issue. There are no dumb questions about detection engineering.
