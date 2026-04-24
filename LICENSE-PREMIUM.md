# ThreatClaw Premium Skills — Commercial License

**Version 1.0 — April 2026**

This license governs the **premium skills** distributed by ThreatClaw through
the official skill marketplace (`hub.threatclaw.io`). It applies exclusively
to skills marked with `"tier": "premium"` in their manifest.

It does **not** apply to the ThreatClaw core, nor to any skill distributed
under the AGPL v3 license (see `LICENSE` at the repository root). Those
remain free and open-source forever.

---

## 1. Parties

- **Licensor** — CyberConsulting.fr (France), operator of ThreatClaw.
- **Licensee** — the natural person or legal entity that has purchased a
  valid License Certificate for one or more Premium Skills.

## 2. Grant of License

Subject to payment of the applicable fees and compliance with this license,
the Licensor grants the Licensee a **non-exclusive, non-transferable,
non-sublicensable, revocable** right to:

1. Download, install, and execute the Premium Skills on the infrastructure
   covered by the Licensee's License Certificate;
2. Use the Premium Skills in production to protect the Licensee's own
   information systems or, if the Licensee is a Managed Service Provider
   (MSP) with an MSP License Certificate, the systems of the Licensee's
   clients;
3. Receive updates and security patches for the term of the License
   Certificate.

## 3. Restrictions

The Licensee **shall not**:

1. **Redistribute, resell, sublicense, rent, or lease** the Premium Skills,
   in whole or in part, to any third party outside the scope of an MSP
   License;
2. **Reverse engineer, decompile, or disassemble** the Premium Skills except
   to the extent such activity is expressly permitted by applicable law
   notwithstanding this restriction;
3. **Remove, alter, or obscure** any copyright, trademark, or license
   notices embedded in the Premium Skills or their binaries;
4. **Circumvent, disable, or tamper with** the license verification
   mechanism, signature checks, or telemetry built into the Premium Skills;
5. **Publish** the source code, decompiled forms, or internal structures of
   the Premium Skills;
6. Use the Premium Skills to provide a **competing SOC-automation product**
   to third parties, outside of a validly licensed MSP arrangement.

## 4. License Types

| Type | Scope | Pricing basis |
|---|---|---|
| **Individual** | One Premium Skill, single deployment site | per-skill, per-site, per-year |
| **Action Pack** | All Premium Skills, single deployment site | per-site, per-year |
| **MSP** | All Premium Skills, unlimited client deployments by the MSP | per-MSP, per-year |
| **Enterprise** | Custom scope (SLA, source escrow, dedicated support) | custom |

The License Certificate issued upon purchase specifies:
- the License Type,
- the included Premium Skills,
- the covered site fingerprint (for non-MSP types),
- the issue date and expiration date,
- the grace period applicable upon expiration (default: 90 days).

## 5. License Verification

The Premium Skills cryptographically verify their License Certificate at
each load using the Licensor's public Ed25519 key, embedded in the
ThreatClaw core. An online revocation check may be performed periodically
against `license.threatclaw.io`; a **90-day offline grace period** applies
if this endpoint is unreachable, to preserve air-gapped deployments.

Upon expiration of the License Certificate (plus any applicable grace
period), the Premium Skills cease to function. The ThreatClaw core and any
free skills continue to operate unaffected.

## 6. Fees and Payment

Fees are set on the marketplace (`hub.threatclaw.io`) and are payable in
advance. All fees are non-refundable except where required by applicable
consumer-protection law (EU Directive 2011/83/EU, 14-day right of
withdrawal for individual consumers).

## 7. Intellectual Property

The Premium Skills, their source code, binaries, documentation, and
associated trademarks remain the **sole and exclusive property of the
Licensor**. No rights are granted beyond those expressly set forth in this
license.

## 8. Warranty Disclaimer

THE PREMIUM SKILLS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. THE
LICENSOR MAKES NO WARRANTY THAT THE PREMIUM SKILLS WILL BE UNINTERRUPTED,
ERROR-FREE, OR SECURE.

In jurisdictions that do not allow the exclusion of implied warranties, the
above exclusion may not apply, and implied warranties are limited in
duration to the shortest period permitted by law.

## 9. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE
LICENSOR BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR
PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS OR REVENUES, WHETHER INCURRED
DIRECTLY OR INDIRECTLY, ARISING FROM THE USE OR INABILITY TO USE THE
PREMIUM SKILLS.

The Licensor's total liability for any claim under this license is limited
to the fees actually paid by the Licensee during the twelve (12) months
preceding the claim.

## 10. Termination

This license terminates automatically upon:

1. expiration of the License Certificate (plus grace period),
2. breach by the Licensee of any term of this license,
3. written notice by the Licensor in case of suspected fraud or abuse.

Upon termination, the Licensee shall cease all use of the Premium Skills
and destroy all copies in its possession. Sections 3, 7, 8, 9, 11, and 12
survive termination.

## 11. Governing Law and Jurisdiction

This license is governed by the **laws of France**, excluding its conflict
of laws rules. Any dispute arising from this license shall be submitted to
the exclusive jurisdiction of the **courts of Paris, France**.

For consumers with residence in another EU Member State, mandatory
consumer-protection provisions of the consumer's country of residence
remain applicable.

## 12. Miscellaneous

- **Entire Agreement** — This license, together with the License
  Certificate and the marketplace terms, constitutes the entire agreement
  between the parties.
- **Severability** — If any provision is held unenforceable, the remaining
  provisions remain in full force.
- **Assignment** — The Licensee may not assign this license without the
  prior written consent of the Licensor. The Licensor may assign this
  license freely, including in connection with a merger, acquisition, or
  sale of assets.
- **Contact** — `contact@cyberconsulting.fr`

---

This license text is versioned. The version in effect at the date of
purchase of a given License Certificate governs that Certificate,
regardless of subsequent amendments.
