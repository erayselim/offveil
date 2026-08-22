# Public Windows beta (`1.0.0-b2`)

No phone-home. Measurement is the GitHub issue form.

## Target networks

x64 Windows 10/11, **Smart App Control off**:

- Turk Telekom / TTNET
- Superonline
- Turksat
- Turkcell
- Vodafone
- At least 2 smaller / regional ISPs

SAC-on is a separate bucket. If install fails, mark it "SAC block" and
leave it out of the success rate. We do not recommend turning SAC off.

## Onboarding

1. GitHub Releases only.
2. Compare `Get-FileHash` with `SHA256SUMS.txt`.
3. SmartScreen: More info, then Run anyway ([antivirus.md](antivirus.md)).
4. SAC on means this beta does not cover you.
5. Defender quarantine: exclude `C:\Program Files\offveil` and tell us.
6. No presets. If it fails, attach the diagnostics zip to the issue.

## Discord within 2 minutes

Issue template: `.github/ISSUE_TEMPLATE/beta.yml`

Required:

- ISP name
- Windows version (10/11 + build)
- SAC on / off
- Did Discord open within **2 minutes** of the toggle? (yes/no)
- Diagnostics zip if possible

Track the "yes" rate on the SAC-off cohort.

## Maintainer, each release

- WDSI submission ([antivirus.md](antivirus.md))
- VirusTotal URL (triage, not a proof)
- Keep the unsigned / SAC / hash wording in the release body
