import type { RequestHandler } from "express";

/**
 * Middleware that returns 404 for requests targeting well-known sensitive file
 * paths that vulnerability scanners commonly probe.
 *
 * Without this, the SPA catch-all returns a 200 with HTML for every unknown
 * path — including `.env`, `.git/config`, etc. — which can signal to attackers
 * that the server is worth further probing.
 *
 * This middleware should be mounted **before** the static-file serving and SPA
 * catch-all so that sensitive paths never reach them.
 */

/**
 * Exact paths that should always return 404.
 */
const BLOCKED_EXACT_PATHS = new Set([
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.env.development",
  "/.env.staging",
  "/.env.backup",
  "/.env.bak",
  "/.env.old",
  "/.env.save",
  "/.env.example",
  "/.npmrc",
  "/.yarnrc",
  "/.dockerenv",
  "/phpinfo.php",
  "/info.php",
  "/wp-login.php",
  "/wp-admin",
  "/wp-config.php",
  "/xmlrpc.php",
  "/administrator",
  "/server-status",
  "/server-info",
  "/.htaccess",
  "/.htpasswd",
  "/.ds_store",
  "/thumbs.db",
  "/web.config",
  "/config.json",
  "/config.yaml",
  "/config.yml",
  "/docker-compose.yml",
  "/docker-compose.yaml",
  "/dockerfile",
  "/makefile",
  "/package.json",
  "/package-lock.json",
  "/composer.json",
  "/composer.lock",
  "/gemfile",
  "/gemfile.lock",
  "/database.yml",
  "/secrets.yml",
  "/credentials.yml.enc",
]);

/**
 * Path prefixes that should always return 404.
 */
const BLOCKED_PATH_PREFIXES = [
  "/.git/",
  "/.svn/",
  "/.hg/",
  "/.aws/",
  "/.ssh/",
  "/.gnupg/",
  "/.config/",
  "/.docker/",
  "/.kube/",
  "/.npm/",
  "/.yarn/",
  "/.vscode/",
  "/.idea/",
  "/_next/data/",      // Next.js internal data routes
  "/cgi-bin/",
  "/wp-includes/",
  "/wp-content/",
  "/vendor/phpunit/",
  "/node_modules/",
  "/.well-known/",     // except acme-challenge, handled by reverse proxy
];

/**
 * File extensions that should return 404 when requested at the root or any
 * non-API path (attackers often probe for backup/config files).
 */
const BLOCKED_EXTENSIONS = new Set([
  ".bak",
  ".backup",
  ".old",
  ".orig",
  ".save",
  ".swp",
  ".swo",
  ".sql",
  ".sql.gz",
  ".tar",
  ".tar.gz",
  ".tgz",
  ".zip",
  ".rar",
  ".7z",
  ".log",
  ".cfg",
  ".ini",
  ".conf",
  ".pem",
  ".key",
  ".crt",
  ".csr",
  ".pfx",
  ".p12",
  ".jks",
]);

export function sensitivePathGuard(): RequestHandler {
  return (req, res, next) => {
    // Only guard non-API GET requests (API routes have their own 404 handler).
    if (req.path.startsWith("/api/")) {
      next();
      return;
    }

    const lowerPath = req.path.toLowerCase();

    // Check exact blocked paths.
    if (BLOCKED_EXACT_PATHS.has(lowerPath)) {
      res.status(404).end();
      return;
    }

    // Check blocked prefixes.
    for (const prefix of BLOCKED_PATH_PREFIXES) {
      if (lowerPath.startsWith(prefix)) {
        res.status(404).end();
        return;
      }
    }

    // Check blocked file extensions.
    const lastDot = lowerPath.lastIndexOf(".");
    if (lastDot !== -1) {
      const ext = lowerPath.slice(lastDot);
      if (BLOCKED_EXTENSIONS.has(ext)) {
        res.status(404).end();
        return;
      }
      // Handle compound extensions like .sql.gz or .tar.gz
      const secondLastDot = lowerPath.lastIndexOf(".", lastDot - 1);
      if (secondLastDot !== -1) {
        const compoundExt = lowerPath.slice(secondLastDot);
        if (BLOCKED_EXTENSIONS.has(compoundExt)) {
          res.status(404).end();
          return;
        }
      }
    }

    next();
  };
}
