# RouteHound

**Forced-browsing scanner for Burp Suite exports**

Version: `1.0.0`
Author: `NiTr0Rc1`

---

## What it does

RouteHound replays every request from a Burp Suite XML export **without authentication** and compares each response against the originally captured one. Any URL whose unauthenticated response still matches the authenticated response (by status code and/or length) is a forced-browsing / broken-access-control candidate.

For each URL it reports:

| Column          | Meaning                                                               |
|-----------------|-----------------------------------------------------------------------|
| `S.No`          | Row number                                                            |
| `URL`           | Target URL (truncated for display)                                    |
| `Burp Status`   | Status code recorded in the Burp XML (authenticated)                  |
| `Burp Len`      | Response length recorded in the Burp XML                              |
| `Unauth Status` | Status code returned when replayed without cookies/headers            |
| `Unauth Len`    | Response length when replayed unauthenticated                         |
| `StatusM`       | `Yes` if both status codes match                                      |
| `LenM`          | `Yes` if the unauth length is within tolerance of the Burp length     |

Length comparison uses a configurable percentage tolerance with a 500-byte floor so small responses are not flagged by noise.

---

## Requirements

- Go `1.21+` (only needed if you want to rebuild)
- A Burp Suite XML export (Target → Site map → `Save selected items` → XML, base64 off is fine)

Only the Go standard library is used — no external dependencies.

---

## Build

```bash
go build -o RouteHound main.go
```

A prebuilt `RouteHound` binary is already included in this directory.

---

## Burpsuite 

```
Target > Sitemap > Save items > Burpsuite.xml
```


## Quick start

```bash
# Scan everything in scope coda.io, write a report, 50 workers
./RouteHound -input Burpsuite.xml -scope coda.io -output report.txt -c 50

# Skip static assets and only show forced-browsing candidates
./RouteHound -input Burpsuite.xml -scope coda.io \
    -file-exclude js,css,png,gif,svg,woff,woff2 \
    -StatusM Yes -LenM Yes

# Only test JavaScript files
./RouteHound -input Burpsuite.xml -file-include js
```

---

## Flags

### Input & Output
| Flag       | Type   | Default         | Description                               |
|------------|--------|-----------------|-------------------------------------------|
| `-input`   | string | `Burpsuite.xml` | Path to the Burp Suite XML export         |
| `-output`  | string | *(none)*        | Write the plain-text table to this file   |

### Scanning
| Flag        | Type     | Default          | Description                                           |
|-------------|----------|------------------|-------------------------------------------------------|
| `-c`        | int      | `10`             | Concurrent request workers                            |
| `-timeout`  | duration | `15s`            | Per-request timeout                                   |
| `-ua`       | string   | `RouteHound/1.0` | User-Agent header on outgoing requests                |
| `-insecure` | bool     | `true`           | Skip TLS certificate verification                     |
| `-follow`   | bool     | `false`          | Follow HTTP redirects (off keeps 3xx responses visible) |

### Scope & Filtering
| Flag                | Type   | Default  | Description                                                       |
|---------------------|--------|----------|-------------------------------------------------------------------|
| `-scope`            | string | *(none)* | Restrict to these hosts and their subdomains (comma-separated)    |
| `-file-include`     | string | *(none)* | Test only URLs with these file extensions (comma-separated)       |
| `-file-exclude`     | string | *(none)* | Skip URLs with these file extensions (comma-separated)            |
| `-length-tolerance` | int    | `10`     | Length-match tolerance in percent (minimum floor: 500 bytes)      |

### Display Filters
| Flag          | Type   | Default  | Description                                           |
|---------------|--------|----------|-------------------------------------------------------|
| `-StatusM`    | string | *(none)* | Show only rows where StatusM equals `Yes` or `No`     |
| `-LenM`       | string | *(none)* | Show only rows where LenM equals `Yes` or `No`        |
| `-no-color`   | bool   | `false`  | Disable ANSI colors                                   |
| `-no-banner`  | bool   | `false`  | Hide the startup banner                               |

### Meta
| Flag        | Type | Default | Description               |
|-------------|------|---------|---------------------------|
| `-version`  | bool | `false` | Print version and exit    |
| `-help`     | bool | `false` | Show the help message     |

---

## How scope matching works

`-scope coda.io` matches `coda.io` **and** any subdomain of it (`api.coda.io`, `cdn.coda.io`, etc.). Pass multiple comma-separated roots to allow more than one.

## How length matching works

A response length matches when the absolute difference between the Burp length and the unauth length is within either:

- `length-tolerance` percent of the larger of the two values, **or**
- `500` bytes (whichever is larger).

This keeps small headers/cache-busters from producing false mismatches on short bodies.

## Response length formula

To align with Burp's `<responselength>`, the computed length is:

```
status line + headers + CRLF + body
```

so the comparison is apples-to-apples with the XML export.

---

## Output

- **stdout** — the live, colorized table (green `Yes`, red `No`).
- **stderr** — banner, config summary, progress ticks every 500 URLs, and the final stats block.
- **`-output <file>`** — a plain-text copy of the table plus the stats block, with no ANSI codes.

Final summary includes:

```
URLs tested
Filtered out by scope/extension
Status matches
Length matches
Errored
Duration
```

---

## Legal

Only run RouteHound against targets you have explicit written authorization to test. Replaying captured traffic without permission is unauthorized access.
