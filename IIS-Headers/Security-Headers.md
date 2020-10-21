Content-Security-Policy
Is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets. frame-ancestors 
Example: frame-ancestors https://DOMAIN.com https://*.DOMAIN.com http://DOMAIN.com http://*.DOMAIN.com (directive specifies valid parents that may embed a page using <frame>, <iframe>, <object>, <embed>, or <applet>.)
 
X-Powered-By (Only for IIS)
A common non-standard HTTP response header
Example: Apache 2.0.59 Commodore C64 (Random)
 

X-Content-Type-Options
Is a marker used by the server to indicate that the MIME types advertised
Example: Nosniff (Search Engines to not Index)
 
Referrer-Policy
Controls how much referrer information (sent via the Referer header) should be included with requests.
Example: strict-origin (Only send the origin of the document as the referrer when the protocol security level stays the same (HTTPS→HTTPS), but don't send it to a less secure destination (HTTPS→HTTP))
 
X-XSS-Protection
Response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks
Example: 1; mode=block (Enables XSS filtering. Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected)
 
Strict-Transport-Security
Often abbreviated as HSTS, Lets a web site tell browsers that it should only be accessed using HTTPS, instead of using HTTP.
Example: max-age=31536000; includeSubDomains (The time, in seconds, that the browser should remember that a site is only to be accessed using HTTPS.)
 
Feature-Policy
Header provides a mechanism to allow and deny the use of browser features in its own frame, and in content within any <iframe> elements in the document.
Example vibrate 'self' (An allowlist is a list of origins that takes one or more of the following values, separated by spaces)
 
Cache-Control
Example: no-cache, no-store
 
Pragma
Example: no-cache

Optional Only

Access-Control-Allow-Origin – CORS is blocked by default
Response header indicates whether the response can be shared with requesting code from the given origin.