# Website Security Headers

Plain-language guide to the security headers `scripts\iis\Set-IisRecommendedSecurityHeaders.ps1` adds to IIS websites: what each one protects against, what it can break, how to roll it out safely, and what it does not cover.

Reviewed 2026-10-02 against OWASP, MDN, web.dev, Microsoft's IIS documentation and RFC 6797 (links at the end). Re-check them when you change the preset.

## What security headers are

Every time a browser loads a page, the server sends a few lines of instructions along with it, called response headers. Security headers are the ones that tell the browser to be careful: only talk to this site over HTTPS, do not let other sites put this page inside a frame, do not run scripts from places the site never uses, and so on.

They cost nothing to send and protect every visitor, but they are a second layer. They make common attacks harder to pull off. They do not fix a bug in the application itself, and a header set wrongly can break parts of a site. That is why the rollout below starts with a dry run.

## Rolling it out safely

1. Dry run. Add `-WhatIf` and read what the script would change. Nothing is written.
2. Watch mode for the content policy. Run with `-CspReportOnly`. The browser reports what the Content Security Policy would have blocked but blocks nothing. Add `-CspReportUri https://...` to have browsers send those reports to a collector you run; without it, reports appear only in each browser's developer console.
3. Click through the main pages, sign in, submit a form, and complete any payment or "sign in with" flow. Read the reports.
4. Enforce. Rerun without `-CspReportOnly` once nothing legitimate is being reported.
5. Check from outside with the checkers under [Checking the result](#checking-the-result).

To undo, open the site in IIS Manager, go to HTTP Response Headers and remove the entries. Native HSTS is turned off from the site's HSTS settings in the same console. With `-RemoveExisting`, the backup report written before the change lists the headers the site had.

## What each header does

| Header                            | In plain words                                                                                                                                                                                                                       | What it can break                                                                                                                                                                                   | Preset value                                                                                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Content-Security-Policy           | A list of where the page may load scripts, styles, images and frames from, and where its forms may send data. If an attacker slips a script into a page, the browser refuses to run it when it comes from somewhere not on the list. | Inline scripts and styles, anything loaded from another site (CDNs, analytics, web fonts), and forms that post to another site, such as some single sign-on and payment pages. Start in watch mode. | `default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'` |
| Strict-Transport-Security (HSTS)  | "Always use HTTPS for this site." After the first visit the browser never tries plain HTTP again, so nobody on the network can intercept that first unencrypted request.                                                             | Any part of the host that still needs plain HTTP. Hard to undo: browsers remember it until the time runs out (one year by default).                                                                 | `max-age=31536000`                                                                                   |
| X-Frame-Options                   | "Only this site may show this page inside a frame." Stops clickjacking, where a hostile page hides yours under an invisible layer and tricks people into clicking.                                                                   | Pages another site is meant to embed.                                                                                                                                                               | `SAMEORIGIN`                                                                                         |
| X-Content-Type-Options            | "Trust the file type the server declared; do not guess." Stops a file uploaded as an image being run as a script.                                                                                                                    | Files the server labels with the wrong type. Fix the label, not the header.                                                                                                                         | `nosniff`                                                                                            |
| Referrer-Policy                   | Controls how much of the current address is passed to the next site a visitor goes to. The preset sends only the site name, never the full path or search terms, and nothing at all when leaving HTTPS for HTTP.                     | Analytics that rely on full addresses from other sites.                                                                                                                                             | `strict-origin-when-cross-origin`                                                                    |
| Permissions-Policy                | Switches off the camera, microphone and location for the page, so a script that should not be there cannot ask for them. Browser support is still uneven, so treat it as an extra layer.                                             | A site that does use one of these. Allow it for the site itself.                                                                                                                                    | `geolocation=(), microphone=(), camera=()`                                                           |
| Cross-Origin-Opener-Policy        | Keeps the page in its own window group, so a page from another site that it opens, or that opened it, cannot reach back into it.                                                                                                     | "Sign in with..." and payment flows that use a popup from another site. Use `-CoopAllowPopups`.                                                                                                     | `same-origin`                                                                                        |
| Cross-Origin-Resource-Policy      | Stops other websites loading this site's images, scripts and files into their own pages.                                                                                                                                             | A host that serves files or widgets to other sites, such as a CDN or an embeddable widget. Change it to `cross-origin` there.                                                                       | `same-site`                                                                                          |
| X-Permitted-Cross-Domain-Policies | Tells old Adobe Flash and Acrobat clients not to load data across sites.                                                                                                                                                             | Nothing current.                                                                                                                                                                                    | `none`                                                                                               |

The script also stops the server announcing what it runs:

- `X-Powered-By` is removed. It tells an attacker the framework and version and protects nothing.
- The `Server` header is removed by turning on IIS request filtering's `removeServerHeader`. Microsoft documents it as working on Windows Server or Windows 10 version 1709 and later. On an IIS that does not know the setting, the script reports the site as `NotRun` instead of claiming success. Use `-KeepServerHeader` to leave it alone.

## Options

| Switch                      | What it does                                                                                                                                                                                                                                                                                               |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-WhatIf`                   | Shows what would change and changes nothing. Always run this first.                                                                                                                                                                                                                                        |
| `-CspReportOnly`            | Sends the content policy in watch mode: report, do not block. X-Frame-Options keeps clickjacking protection in force meanwhile.                                                                                                                                                                            |
| `-CspReportUri <https URL>` | Adds a reporting address to the content policy (both the current `report-to` mechanism and the older `report-uri` one) and the matching `Reporting-Endpoints` header. The address must be HTTPS; browsers ignore plain-HTTP report addresses. You need a service at that address that accepts the reports. |
| `-CoopAllowPopups`          | Uses `same-origin-allow-popups` for Cross-Origin-Opener-Policy, so sign-in and payment popups from other sites keep working.                                                                                                                                                                               |
| `-UseNativeHsts`            | Uses IIS's built-in HSTS setting (IIS 10 version 1709 or later) instead of a custom header. Recommended where supported, see below.                                                                                                                                                                        |
| `-RedirectHttpToHttps`      | With `-UseNativeHsts`, also has IIS send every plain-HTTP request to HTTPS.                                                                                                                                                                                                                                |
| `-HstsIncludeSubDomains`    | Extends HSTS to every name under the site. Only after every one of them works over HTTPS. The script never adds `preload`.                                                                                                                                                                                 |
| `-HstsMaxAgeSeconds`        | How long browsers remember HSTS. Default one year. Start with a few minutes (300) on a host you are unsure of, then raise it.                                                                                                                                                                              |
| `-IncludeNoStore`           | Adds `Cache-Control: no-store`, so browsers keep no copy of any page. Only for sites where every page is sensitive; it also stops caching of images and scripts.                                                                                                                                           |
| `-KeepServerHeader`         | Leaves the `Server` header setting alone.                                                                                                                                                                                                                                                                  |
| `-RemoveExisting`           | Clears the site's existing custom headers first, after writing a backup report.                                                                                                                                                                                                                            |
| `-Headers @{...}`           | Replaces the preset with exactly the headers you pass. Cannot be combined with `-CspReportOnly`, `-CspReportUri`, `-CoopAllowPopups` or `-IncludeNoStore`.                                                                                                                                                 |

## Things to know before you rely on it

- A deployment can wipe the headers. The script writes custom headers into the site's own `web.config`. A deployment that replaces that file removes them silently. Either have the developers put the same headers in the application's own `web.config` so they ship with every release, or rerun the script after each deployment and check from outside. Native HSTS (`-UseNativeHsts`) and server-level settings live outside the site's `web.config` and survive.
- Set each header in one place. If the application also sends a content policy, the browser enforces both, and anything either one blocks is blocked. Duplicate X-Frame-Options values can also be misread by checkers. Decide whether IIS or the application owns each header.
- Native HSTS is the better choice where IIS supports it. The custom header is also sent on plain-HTTP responses, where browsers ignore it as the HSTS standard requires (RFC 6797, section 8.1). It does no harm, but scanners may flag it. `-UseNativeHsts` sends it on HTTPS only.
- `SAMEORIGIN` is a compromise. OWASP recommends `DENY`, which stops all framing. The preset uses `SAMEORIGIN` because many sites frame their own pages. If yours never does, pass `X-Frame-Options = 'DENY'` and `frame-ancestors 'none'` with `-Headers`.
- The preset content policy is a starting point, not the strongest one. It lists allowed places, and a policy built on a list of places can still be bypassed in some cases (web.dev). The strongest form, a "strict" policy, marks each allowed script with a one-time code that must change on every page load. IIS cannot generate that code, so that step is the application developers' job.

## What this does not cover

Headers are one control among several. These need their own work:

- Cookies: the `Secure`, `HttpOnly` and `SameSite` flags are set by the application (see the OWASP Session Management Cheat Sheet).
- TLS: protocol versions and cipher suites are a server setting, not a header.
- ASP.NET version headers: `X-AspNet-Version` and `X-AspNetMvc-Version` come from the application. Turn them off in its `web.config` (`<httpRuntime enableVersionHeader="false" />`) and, for MVC, in code (`MvcHandler.DisableMvcResponseHeader = true`).
- Caching of sensitive pages: an application should send `Cache-Control: no-store` on pages with personal or account data, rather than setting it on the whole site.
- Responses Windows sends before IIS sees the request carry `Server: Microsoft-HTTPAPI/2.0`. Removing that needs the registry value `DisableServerHeader` set to 2 under `HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters`, which this script does not touch.

## Do not send these any more

| Header                                        | Why                                                                                                                                                                                                                                                         |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `X-XSS-Protection: 1; mode=block`             | It switched on an old browser filter that could itself be abused. MDN warns it "can create XSS vulnerabilities in otherwise safe websites". OWASP says not to set it, or to set it to `0`, and to rely on the content policy. The posture checker flags it. |
| `Feature-Policy`                              | Replaced by `Permissions-Policy`, which uses a different syntax.                                                                                                                                                                                            |
| `Pragma: no-cache`                            | An old request instruction with no defined meaning on a response. `Cache-Control` replaces it.                                                                                                                                                              |
| A fake `X-Powered-By` value                   | Advertises that something is being hidden and stops nothing. Remove the header.                                                                                                                                                                             |
| `Expect-CT`, `Public-Key-Pins`                | Obsolete. OWASP says not to use them; a wrong `Public-Key-Pins` value can lock visitors out of the site.                                                                                                                                                    |
| `Access-Control-Allow-Origin: *` as a default | Sharing across sites is closed by default. Only an application meant to be read by other sites should open it, and only to named sites.                                                                                                                     |

## Checking the result

`scripts\web\Test-ExternalSecurityPosture.ps1`, `Test-HstsAndHttpExposure.ps1` and `Test-ClickjackingProtection.ps1` read the headers from outside, the way a scanner does, and need PowerShell 7.4 or later. The posture sweep also flags X-XSS-Protection left on, a missing or `unsafe-url` Referrer-Policy, and a missing Permissions-Policy.

A site with the default preset still draws an "HSTS without includeSubDomains" finding until you add that flag. That is intended: the flag commits every name under the site to HTTPS, which is a decision about all of them, not this one.

## Sources

- OWASP HTTP Headers Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html>
- OWASP Content Security Policy Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
- OWASP Secure Headers Project: <https://owasp.org/www-project-secure-headers/>
- web.dev, Mitigate cross-site scripting with a strict CSP: <https://web.dev/articles/strict-csp>
- MDN, Content-Security-Policy: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy>
- MDN, CSP form-action: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action>
- MDN, Reporting-Endpoints: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Reporting-Endpoints>
- MDN, Strict-Transport-Security: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security>
- MDN, X-Frame-Options: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options>
- MDN, Referrer-Policy: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy>
- MDN, Permissions-Policy: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy>
- MDN, Cross-Origin-Opener-Policy: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy>
- MDN, Cross-Origin-Resource-Policy: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy>
- MDN, X-XSS-Protection: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection>
- MDN, X-Permitted-Cross-Domain-Policies: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Permitted-Cross-Domain-Policies>
- RFC 6797, HTTP Strict Transport Security: <https://www.rfc-editor.org/rfc/rfc6797>
- Microsoft, IIS request filtering (`removeServerHeader`): <https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/>
- Microsoft, the site `<hsts>` element: <https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/hsts>
- Microsoft, IIS 10 version 1709 HSTS support: <https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10-version-1709/iis-10-version-1709-hsts>
