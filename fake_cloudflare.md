# "You've Run Out Of Storage!": Anatomy of a Fake Cloudflare Check Hosted on Google Cloud Storage

*A threat writeup, with commentary.*

**Status:** Published (Initial Analysis) | **Observed:** 2026-10-28 | **Category:** Phishing / scam funnel (suspected) | **Author:** Schyler Horn @AkibaReject

## TL;DR

An email told me my cloud storage was full. It also told me a payment had failed. These are different problems, and the sender picked both. The link led to a tiny static page in a public Google Cloud Storage bucket that:

1. Pretends to be a Cloudflare browser check.
2. Hides its destination behind XOR-encoded strings.
3. Quietly turns away scanners and researchers (cloaking).
4. Loads the real Cloudflare Turnstile widget so the fake check looks legitimate.
5. Forwards the visitor to a second site, which I did not visit because I enjoy my laptop.

Net result: a cloaked redirector with a fake verification step and a surprising amount of commitment to the bit. Nothing was executed during analysis; I only read it and judged it.

## Scorecard

Grading the threat actor, because someone should.

| Category | Grade | Comment |
|---|---|---|
| Lure coherence | C- | Subject says storage full, body says payment failed. Pick a lane. |
| Email authentication | D | SPF passed for a domain unrelated to the From line. Three domains, zero alignment. |
| Obfuscation | B- | XOR instead of base64 shows initiative. See "A Brief Note on XOR." |
| Cloaking | B+ | Genuinely thoughtful, and the most professional part of the operation. |
| Audacity | A | Used the recipient's own username as the sender name. Bold. |
| Operational security | C | Left the Turnstile site key in the page. Cloudflare will want a word. |
| Filler content | Incomplete | Includes recycled forum text and a French job-application template. Nobody asked. |

## Methodology

1. Received the link in an unsolicited email on 2026-10-12. Headers and body were reviewed (see Email Analysis); recipient details and per-recipient tracking values are redacted.
2. Requested headers only with `curl -I` from a terminal. No JavaScript was executed. (See Lessons Learned for what I did to the URL.)
3. Saved and reviewed page source as text (initial paste was truncated).
4. Statically decoded the XOR-encoded strings in the inline script to recover its URLs, parameter names, and Turnstile site key. No code was executed.
5. _(Optional)_ Submitted the URL to a sandbox such as urlscan.io or VirusTotal. Results: _add link/summary_.

## Delivery

| Item | Observation |
|---|---|
| Lure | Bulk email, subject "Warning! Your Cloud Storage Is Full", delivered 2026-10-12 (about three days after the page was uploaded) |
| Host | Public Google Cloud Storage bucket |
| Why it works | The trusted `googleapis.com` domain lends credibility and can help links pass basic filters. Anyone can create a bucket; hosting there does not imply Google vetting. |

Using a reputable domain to host a disreputable page is the web equivalent of wearing a hi-vis vest to walk into a building.

## Email Analysis

Recipient addresses, the recipient's mailbox username, the Message-ID, the envelope-sender token, signature values, and per-recipient tracking values are redacted.

### Authentication results

| Check | Result | Notes |
|---|---|---|
| SPF | Pass | Passes only for the envelope-sender domain (a `stonefitness[.]biz[.]id` subdomain) from `51[.]68[.]59[.]249`. This shows the IP may send for a domain the sender controls; it says nothing about the visible From domain. |
| DKIM | Fail | Signed with `rsa-sha1` by `nohe[.]sb038[.]stonefitness[.]biz[.]id`, a third domain unrelated to the From domain. A legacy DomainKey-Signature is also present. |
| DMARC | Fail | Visible From domain `sdzvp[.]mxq` does not align with the SPF or DKIM domains, and `.mxq` does not appear to be a delegated TLD. |

One pass and two fails. In this case, that is not "mostly fine."

### Header anomalies

1. **Three unrelated domains** appear for one message: visible From (`sdzvp[.]mxq`), envelope/DKIM (`stonefitness[.]biz[.]id` subdomains), and HELO (`sb038[.]site`). A message with this many identities has either a very complicated personal life or something to hide.
2. **Recipient impersonation:** the From display name, Sender, and DKIM identity reuse the recipient's own mailbox username, so the message appears to come from the recipient themselves (redacted). Receiving an email from yourself warning you about your own storage is a bold approach to customer service.
3. **Likely forged Received hop:** one hop claims to come from `efianalytics[.]com` (`216[.]244[.]76[.]116`). Its ID field contains the campaign click-URL string instead of a normal queue ID, it sits outside the normal hop order, and its timestamp mixes `+0000` with a `(PDT)` label. Only the hop recorded by the receiving server is trustworthy, so this one is unverified and probably injected.
4. **Tracking in the envelope sender:** the Return-Path local part is a numeric token that appears to embed campaign tracking values (redacted), consistent with per-recipient bounce tracking.
5. **Malformed or contradictory headers:** the Content-Transfer-Encoding is a random string rather than a valid encoding, two different Content-Length values are present, there are duplicate Delivered-To headers, and `multipart/digest` is used to carry HTML parts. These appear designed to confuse filters and parsers. They also confuse analysts, so, mission accomplished, I suppose.
6. **Self-declared trust:** an `X-Google-Sender-Delegation ... Trusted Sender` header and the body text "This message was sent from a trusted sender" are sender-supplied and carry no weight. Source: trust me, bro.
7. **Unresolvable list-unsubscribe domain:** `NzMW3w9[.]mxq`, which is also the Message-ID domain.
8. **Sender-supplied origin hints:** `X-Originating-IP` (`217[.]18[.]210[.]147`) and a reference to `vevida[.]net` in an `X-Google-Original-Message-ID`. Both are unverified.
9. **Delivery hop:** the receiving server logged TLS 1.0 with a legacy CBC cipher suite, consistent with old bulk-mailer defaults.

### Body

The first MIME part is base64-encoded HTML (despite the bogus declared encoding). Yes, base64. Hold that thought.

- **Lure:** a generic "Cloud Payment Notice" saying a storage renewal payment failed, with a fake subscription ID (`CLDSTRG-92837465`) and an "Update payment method" button. No real provider is named, which is a strong brand strategy if the brand is "no one."
- **Link routing:** the whole notice is wrapped in a link to the bucket URL with `act=cl`. The "unsubscribe" link points to the same bucket with `act=un`, so even the opt-out leads into the funnel. Commitment to the bit.
- **Filter evasion:** large amounts of unrelated filler text (including French-language and forum-style text and template placeholders), randomly named HTML elements, and hidden zero-size divs padded with non-breaking spaces. These appear intended to dilute spam scoring and defeat hash-based signatures.
- **Hidden comment block:** the HTML contains a commented-out block with what appears to be a third party's personal details. It is intentionally not reproduced here and should be treated as PII.

The second MIME part is a hidden `<object>` block with the "trusted sender" text and more invisible spacer content.

## HTTP Response (headers only)

| Header | Value |
|---|---|
| Status | `200 OK` |
| Content-Type | `text/html` |
| Content-Length | 4283 bytes |
| Last-Modified | Fri, 09 Oct 2026 10:06:20 GMT |
| ETag / MD5 | `9860e4868a34123d66943322acbb0c7d` |
| x-goog-generation | `1791540380026683` |
| Server | UploadServer (Google Cloud Storage) |
| Redirect header | None (any redirect is client-side) |

Note: the `x-goog-hash` MD5 base64 value (`mGDkhoo0Ej1mlDMirLsMfQ==`) decodes to the same hex digest as the ETag.

Four kilobytes. For comparison, a real security check has a lot more going on than a 4 KB sticky note with a spinner on it.

## Page Characteristics (observable)

- **Impersonation:** Title "Just a moment..." plus spinner and "Checking your browser..." heading mimic a Cloudflare interaction page. The logo is hotlinked from a third-party image site, not Cloudflare infrastructure.
- **Real Cloudflare behavior for contrast:** genuine challenge pages are served from the protected site's own domain, not from a storage bucket.
- **Obfuscation:** the inline `<script>` stores its strings as XOR-encoded numeric arrays that are decoded at runtime, which hides the parameter names, destination URLs, and library references from simple string scanning.
- **Parameter gating (cloaking):** on load, the page requires four query parameters (`act`, `pid`, `uid`, `vid`). If any is missing, it redirects to a `storage.googleapis.com/.../__not_found__.html` decoy (likely intended for scanners and researchers), so a bare-URL scan may show nothing harmful. The remaining parameters (`ofid`, `lid`, `cid`) are not part of this check. A bot check designed to avoid bots is a nice bit of irony.
- **Fake verification flow:** the page builds a "Verification Successful! Redirecting you now..." state with a spinner and success icon, and loads the genuine Cloudflare Turnstile library with the site key listed under Indicators. Using the real widget makes the check look authentic, and the site key ties the page to the operator's Cloudflare account. "Verification Successful" is doing a lot of work here, given that nothing was verified.
- **Onward redirect:** after the fake check, the visitor is sent to `http://pociv[.]site/`.
- **Tracking-style parameters:** `act`, `pid`, `uid`, `vid`, `ofid`, `lid`, `cid` (values omitted; they may identify the recipient).

_Behavior of `pociv[.]site` (credential harvesting, ad/affiliate fraud, malware delivery, or further redirects): not yet determined. Add sandbox results here._

### A Brief Note on XOR

The author chose XOR over base64, and I respect the ambition.

- Base64 is an encoding everyone recognizes on sight, like a trench coat on a cartoon villain. XOR is the same trench coat with a fake mustache.
- XOR is for when base64 is too readable and real encryption is too much paperwork.
- Calling this "obfuscation" is generous. It is security through mild inconvenience, and the decoder fits in a single line.
- The email body, meanwhile, used plain base64. So the operation has exactly one layer of ambition, and it was spent on the page.

Obfuscation rating: 4 out of 10. Defeats string matching, loses to anyone with a text editor and a free afternoon.

## Indicators of Compromise

Defanged. Do not browse these.

```
hxxp://storage[.]googleapis[.]com/midfielders/midfielders[.]html
Bucket name:   midfielders
Object:        midfielders.html
Query params:  act, pid, uid, vid, ofid, lid, cid (values omitted; per-recipient tracking)
MD5 (header):  9860e4868a34123d66943322acbb0c7d
Image host:    1000logos[.]net (legitimate site, abused via hotlink)
Redirect dest: hxxp://pociv[.]site/
Decoy URL:     storage[.]googleapis[.]com/.../__not_found__[.]html (path partially recovered)
Turnstile key: 0x4AAAAAACdZEBnQFyO9qFll (attacker-registered Cloudflare Turnstile site key)
Gate params:   act, pid, uid, vid

# Email infrastructure (header values may be forged; verify with WHOIS/passive DNS)
Subject:       Warning! Your Cloud Storage Is Full
From domain:   sdzvp[.]mxq
Envelope/DKIM: nohe[.]sb038[.]stonefitness[.]biz[.]id, sb038[.]stonefitness[.]biz[.]id
HELO:          sb038[.]site
Sending IP:    51[.]68[.]59[.]249 (rDNS yubuyazpp[.]app[.]iptv[.]telecom[.]pt)
Forged hop:    efianalytics[.]com / 216[.]244[.]76[.]116 (unverified)
Header IP:     217[.]18[.]210[.]147 (sender-supplied X-Originating-IP; unverified)
Header host:   vevida[.]net (sender-supplied; unverified)
List-Unsub:    NzMW3w9[.]mxq
Fake sub ID:   CLDSTRG-92837465
```

SHA-256 of the full file: _compute with `sha256sum page.html` and add here_.

## MITRE ATT&CK Mapping (tentative)

| Technique | ID | Basis |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Emailed link to hosted page |
| Obfuscated Files or Information | T1027 | XOR-encoded strings in inline script |
| Masquerading | T1036 | Fake Cloudflare verification UI |
| User Execution: Malicious Link | T1204.001 | Requires victim to open link |

## Detection Ideas

- Flag emailed links to `storage.googleapis.com/<bucket>/*.html` combined with tracking-style query strings.
- Flag HTML pages titled "Just a moment..." served from non-Cloudflare origins.
- Match on the object hash or bucket name above.
- Flag pages that load the Cloudflare Turnstile library from a non-Cloudflare-protected origin, especially with the site key above.
- Block or alert on `pociv[.]site`.
- Flag mail where the From domain, envelope-sender domain, and DKIM `d=` domain are all different and DKIM and DMARC both fail.
- Flag malformed MIME (invalid Content-Transfer-Encoding, `multipart/digest` carrying HTML) in bulk mail.

## Lessons Learned

1. **Quote your URLs.** I pasted the link into `curl` without quotes, and the shell helpfully treated each `&` as "run this in the background," launching six jobs and then acting like that was my idea. Harmless here, but a reminder that the terminal does exactly what you typed, not what you meant.
2. **Headers first.** Fetching headers before anything else told me a lot (a tiny file, a storage bucket, no server-side redirect) without running anything.
3. **Scanners get the decoy.** If a bare URL looks clean, the full URL may not. Cloaking makes "it looked fine" a poor defense.
4. **Redact before you publish.** The sender reused my own mailbox name in several headers, and per-recipient tracking values were scattered everywhere. A writeup is only useful if the author is not in it.

## Recommendations for Users

- Do not click "update your payment method" links in unexpected emails. Go to the provider's site directly, typed or bookmarked.
- A "Verifying you are human" screen that appears from an email link is not a good sign. Real ones do not ask you to run commands or paste things.
- Report it: your mail provider's phishing button, the hosting provider's abuse form, and APWG.
- A password manager helps here, because it will not autofill on a domain it does not recognize.

## Limitations

- Static analysis only; the page was not rendered and `pociv[.]site` was not visited or analyzed.
- Decoded values come from the author's own analysis of the encoded strings. The decoy path is only partially recovered.
- The decoy's purpose (evading scanners/researchers) is an inference from the gating logic, not confirmed.
- Behavior may vary by browser, geography, referrer, and user agent.
- Conclusions about the campaign type (affiliate/click-fraud vs. credential theft vs. malware delivery) are unconfirmed.
- Header-derived infrastructure may be forged or belong to legitimate hosts and should be verified before attribution.

## Redactions

To protect the recipient, this writeup omits: recipient email addresses, the recipient's mailbox username (which the sender reused in several headers), the Message-ID, the envelope-sender token, DKIM/ARC signature values, per-recipient tracking values, the exact delivery time, and personal details found in a hidden comment in the email body. The raw `.eml` file is intentionally not included.

## Disclaimer

Published for defensive and educational purposes. Indicators are defanged; do not visit them from a production machine. No scammers were harmed in the making of this document, though their feelings may be.
