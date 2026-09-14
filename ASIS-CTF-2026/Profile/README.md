# Profile — ASIS CTF 2026

**Room / Challenge:** Profile (Web)

**Metadata**

* Author: Kasra
* CTF: ASIS CTF 2026
* Challenge: Profile (web)
* Difficulty: Hard
* Points: 54
* Date: 29-08-2026 / 7/6/1405

## Goal

The challenge only showed a QR / barcode image with the hint:

> Still got an old phone lurking in your rig?

The goal was to obtain the secret eSIM profile and extract the flag from it — without needing a physical eUICC.

## Recon

Instance:
91.107.243.187:80

Decoding the QR produced an **LPA activation code**:
LPA:1$dpp.asisctf.com$

So the backend is a **GSMA SGP.22** SM-DP+ style service at `dpp.asisctf.com`, speaking the **ES9+** interface.

Relevant endpoints used during the solve:

* `/gsma/rsp2/es9plus/initiateAuthentication`
* `/gsma/rsp2/es9plus/authenticateClient`
* `/gsma/rsp2/es9plus/getBoundProfilePackage`
* (and the intermediate prepare-download step)

## Exploitation (device-less)

Because no real eSIM hardware was available, the full client side of the RSP flow was reimplemented in Python:

1. **InitiateAuthentication**  
   Send a crafted `EUICCInfo1` / challenge and receive the server nonce and transaction data.

2. **AuthenticateClient**  
   Build and sign the required ASN.1 structures (`euiccSigned1`, certificate chain material, etc.) so the SM-DP+ accepts the client as a legitimate eUICC.

3. **PrepareDownload / GetBoundProfilePackage**  
   Complete the download handshake and obtain the **Bound Profile Package (BPP)**.

4. **BPP decryption**  
   The package follows the BSP / SCP03-style protection used by the reference (osmo-smdpp-like) stack:
   * derive session keys
   * decrypt each segment with the correct ICV / block-counter handling
   * recover the Unprotected Profile Package (UPP)

5. **Flag extraction**  
   Inside the decrypted profile, the interesting data sits in **ADN phonebook records** (and related PE-Header identification fields).  
   Comparing several `RPROFILE*` variants showed that most contacts were the standard Osmocom test strings, while one set of entries carried the flag fragments. Concatenating those pieces yielded the final flag.

## Notes

* The hard part was not “having a phone” — it was correctly implementing the ASN.1 / ECDSA / BPP crypto so the remote SM-DP+ would hand out a real package.
* Wrong ICV / block-counter handling produced garbage after the first block even when the first block looked plausible (`GSMA…`). Fixing the per-segment ICV logic was the turning point.
* No physical eUICC was required end-to-end.

## Flag
ASIS{as!S_1n_T3lC0_fr0MN_oW}
