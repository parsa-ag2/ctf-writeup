# 2048 — ASIS CTF 2026

**Room / Challenge:** 2048 (Web)

**Metadata**

* Author: Kasra
* CTF: ASIS CTF 2026
* Challenge: 2048 / Citadel Grid (web)
* Difficulty: Medium
* Points: 29
* Date: 29-08-2026 / 7/6/1405

## Goal

Recover the flag from the Council's session-replication toy — a clustered 2048 game whose every move is mirrored through an encrypted garage gateway.

## Recon

The instance was given as:
91.107.164.78:8080
textThe main page is a classic 2048 board with:

* **Score / Best**
* **About** — describes the app as "The Council's official session-replication toy" and mentions the **encrypted garage gateway** built by the garage division
* **Hall of Meseex** — a leaderboard full of suspicious names (`cycler.__init__`, `portal-gun`, `.__class__`, `applicationScope`, …) that already hinted at gadget / object-pollution style attempts

`robots.txt` pointed to:
/citadel/lab-notes.html
textThat page was the real architecture document. Key facts extracted from it:

* Session replication goes through a **Tomcat Tribes** cluster
* There is a binary **garage gateway on TCP 4000**
* The gateway has an **AES/CBC/PKCS5Padding fallback** path
* The stack uses **Apache Commons Collections 3.2.1** (known gadget chains)
* Internal paths of interest: `vault/`, `gate/`, `diagnostics.jsp`, `mirror.jsp`

Requesting `diagnostics.jsp` with a spoofed internal address:

```http
X-Forwarded-For: 127.0.0.1
confirmed the internal view of the cluster and reinforced that the dangerous surface was the replication / gateway path, not the public 2048 UI itself.
Exploitation
The public HTTP surface only hosts the game and a few JSP helpers. The actual attack surface is the encrypted garage gateway on port 4000, which accepts cluster messages and, on the AES-fallback path, deserializes attacker-controlled payloads with a vulnerable Commons Collections version.
High-level chain:

Build a CommonsCollections gadget (ysoserial-style CC6 / CC7) that executes a command or writes a shell.
Wrap the serialized blob in the format expected by the garage gateway (AES/CBC with the fallback key material described in the lab notes).
Send the packet to 91.107.164.78:4000.
The Tribes / gateway path deserializes the payload → RCE in the context of the application.

After code execution it was possible to read the protected material under the vault/gate area (and via helpers such as mirror.jsp) and obtain the flag.
Notes

The 2048 UI and the leaderboard were mostly a distraction; the real vulnerability lived in the session-replication / garage gateway path.
Spoofing X-Forwarded-For only helped for diagnostics, not for the final RCE.
Bruteforcing the game score was never required.

Flag
textASIS{t0McAT_was_Th3_KEY}
