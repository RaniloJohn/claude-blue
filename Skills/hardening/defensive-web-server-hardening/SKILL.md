---
name: defensive-web-server-hardening
description: "Hardening web servers and reverse proxies (nginx, Apache httpd, Microsoft IIS, Caddy, Tomcat/Java app servers, Node.js behind proxies): minimal modules, version/banner suppression, TLS configuration, security headers, request size/timeouts and rate limiting, directory listing and file exposure prevention (.git, .env, backups), PHP/runtime hardening, running as unprivileged users with read-only web roots, disabling dangerous HTTP methods, admin interface restriction, logging formats for security, file integrity monitoring, and CIS benchmark alignment. Use when configuring or auditing web servers."
---

# Web Server Hardening

Most web server compromises exploit the **application**, but server configuration decides the blast radius and what leaks. Minimize, restrict, log.

## Quick Workflow

1. Patch server and runtime; remove unused modules
2. Run as unprivileged user; web root read-only to the service
3. TLS + security headers (`defensive-tls-pki`, `defensive-waf`)
4. Block sensitive file exposure and directory listing; restrict admin paths
5. Limits and timeouts; rate limiting on sensitive endpoints
6. Security-useful logging + FIM; scan with CIS benchmarks

---

## 1. nginx

```nginx
server_tokens off;
client_max_body_size 10m;
client_body_timeout 10s; client_header_timeout 10s; keepalive_timeout 15s; send_timeout 10s;
autoindex off;
location ~ /\.(?!well-known) { deny all; }                       # .git, .env, .htaccess
location ~* \.(bak|old|orig|swp|sql|tar|gz|zip|7z)$ { deny all; }
location /admin { allow 10.20.0.0/16; deny all; }
if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$) { return 405; }
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/s;
location = /login { limit_req zone=auth burst=10 nodelay; proxy_pass http://app; }
log_format sec '$remote_addr - $remote_user [$time_iso8601] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" rt=$request_time xff="$http_x_forwarded_for" host=$host';
access_log /var/log/nginx/access.log sec;
```

---

## 2. Apache httpd

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
Options -Indexes -Includes -ExecCGI +FollowSymLinks
<DirectoryMatch "/\.(?!well-known)"> Require all denied </DirectoryMatch>
<FilesMatch "\.(bak|old|orig|swp|sql|env|ini|log)$"> Require all denied </FilesMatch>
LimitRequestBody 10485760
Timeout 30
RequestReadTimeout header=10-20,MinRate=500 body=20,MinRate=500
```

Disable unused modules (`a2dismod status autoindex cgi` on Debian), protect `mod_status`/`server-info` to localhost.

---

## 3. IIS

- Remove unused role services (WebDAV, CGI if not needed); Request Filtering: deny double escaping, hidden segments (`web.config`, `bin`, `App_Data`), file extensions, verbs (TRACE)
- `removeServerHeader="true"` (IIS 10+), remove `X-Powered-By`, `X-AspNet-Version` (`enableVersionHeader="false"`)
- Application pool identities (ApplicationPoolIdentity), one pool per app
- Disable directory browsing; custom errors (no detailed errors remotely)
- IIS logging with W3C fields including `cs(User-Agent)`, `X-Forwarded-For` (custom field); watch for webshells (`w3wp.exe` child processes)

---

## 4. Runtime Hardening

| Runtime | Settings |
|---|---|
| PHP | `expose_php=Off`, `display_errors=Off`, `allow_url_include=Off`, `disable_functions` (exec, system, shell_exec, passthru, proc_open, popen) where app allows, `open_basedir`, separate FPM pools per site |
| Java / Tomcat | Remove default apps (manager, host-manager, examples, docs) or restrict to localhost; shutdown port disabled; latest JDK |
| Node.js | Behind reverse proxy; `NODE_ENV=production`; helmet middleware for headers; don't run as root |

---

## 5. File System & Process

- Service runs as dedicated user (`www-data`, app pool identity); web root owned by deploy user, read-only for service; upload dirs non-executable (`noexec` mount or deny script execution)
- No source control metadata or secrets in web root (`.git/`, `.env`) — verify externally: `curl -I https://site/.git/HEAD`
- FIM on web roots and configs; alert on new script files (`defensive-web-compromise-response`)

---

## 6. Verify

```bash
curl -sI https://www.example.com | grep -iE 'server|x-powered-by|strict-transport|content-security'
curl -s -o /dev/null -w "%{http_code}\n" https://www.example.com/.git/HEAD     # expect 403/404
nmap --script http-methods,http-headers -p 443 www.example.com                # authorized targets only
testssl.sh www.example.com
```

CIS Benchmarks for NGINX, Apache HTTP Server, IIS; Lynis web checks on Linux hosts.

---

## Engagement Cheatsheet

```text
patch + minimal modules → unprivileged user, read-only webroot, noexec uploads → TLS + headers → deny dotfiles/backups/listing, restrict admin, limit methods
→ size limits/timeouts/rate limits → runtime hardening (PHP/Tomcat/Node) → security log format + FIM → verify (curl, nmap, testssl) + CIS
```

---

## Key References

- CIS Benchmarks (NGINX, Apache, IIS); Mozilla web security guidelines; OWASP Secure Headers Project; vendor hardening guides
- Related: `defensive-tls-pki`, `defensive-waf`, `defensive-web-compromise-response`, `defensive-linux-hardening`
