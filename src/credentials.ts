import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import {
  readAllClaudeAccounts,
  refreshAccount,
  writeBackCredentials,
  type ClaudeCredentials,
  type ClaudeAccount,
} from "./keychain.ts"
import { resetExcludedBetas } from "./betas.ts"
import { log } from "./logger.ts"

/**
 * Centralized audit log — shared with refresh service and usage bar.
 */
function audit(action: string, profile: string, detail: string = ""): void {
  try {
    const path = join(homedir(), ".local", "share", "opencode", "credentials-audit.log")
    const ts = new Date().toISOString()
    appendFileSync(path, `${ts} | plugin:${process.pid} | ${action} | ${profile} | ${detail}\n`)
  } catch {
    // Non-fatal
  }
}

export type { ClaudeCredentials } from "./keychain.ts"
export type { ClaudeAccount } from "./keychain.ts"

const CREDENTIAL_CACHE_TTL_MS = 30_000

const accountCacheMap = new Map<
  string,
  { creds: ClaudeCredentials; cachedAt: number }
>()
let activeAccountSource: string | null = null
let allAccounts: ClaudeAccount[] = []

export function initAccounts(accounts: ClaudeAccount[]): void {
  allAccounts = accounts
}

export function getAccounts(): ClaudeAccount[] {
  return allAccounts
}

export function setActiveAccountSource(source: string): void {
  const previous = activeAccountSource
  activeAccountSource = source
  accountCacheMap.delete(source)
  resetExcludedBetas()
  if (previous && previous !== source) {
    log("account_switch", { newSource: source, previousSource: previous })
  }
}

export function refreshAccountsList(): ClaudeAccount[] {
  allAccounts = readAllClaudeAccounts()
  return allAccounts
}

function getActiveAccount(): ClaudeAccount | null {
  if (allAccounts.length === 0) return null
  if (activeAccountSource) {
    const found = allAccounts.find((a) => a.source === activeAccountSource)
    if (found) return found
  }
  return allAccounts[0]
}

function getAccountStateFile(): string {
  return join(
    homedir(),
    ".local",
    "share",
    "opencode",
    "claude-account-source.txt",
  )
}

export function loadPersistedAccountSource(): string | null {
  try {
    const path = getAccountStateFile()
    if (existsSync(path)) {
      return readFileSync(path, "utf-8").trim() || null
    }
  } catch {
    // ignore
  }
  return null
}

export function saveAccountSource(source: string): void {
  try {
    const path = getAccountStateFile()
    const dir = dirname(path)
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    writeFileSync(path, source, "utf-8")
  } catch {
    // Non-fatal
  }
}

function getAuthJsonPaths(): string[] {
  const xdgPath = join(homedir(), ".local", "share", "opencode", "auth.json")
  if (process.platform === "win32") {
    const appData =
      process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local")
    const localAppDataPath = join(appData, "opencode", "auth.json")
    return [xdgPath, localAppDataPath]
  }
  return [xdgPath]
}

function syncToPath(authPath: string, creds: ClaudeCredentials): void {
  let auth: Record<string, unknown> = {}
  if (existsSync(authPath)) {
    const raw = readFileSync(authPath, "utf-8").trim()
    if (raw) {
      try {
        auth = JSON.parse(raw)
      } catch {
        // Malformed file, start fresh
      }
    }
  }
  auth.anthropic = {
    type: "oauth",
    access: creds.accessToken,
    refresh: creds.refreshToken,
    expires: creds.expiresAt,
  }
  const dir = dirname(authPath)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
  }
  writeFileSync(authPath, JSON.stringify(auth, null, 2), {
    encoding: "utf-8",
    mode: 0o600,
  })
  if (process.platform !== "win32") {
    chmodSync(authPath, 0o600)
  }
}

export function syncAuthJson(creds: ClaudeCredentials): void {
  for (const authPath of getAuthJsonPaths()) {
    try {
      syncToPath(authPath, creds)
      audit("auth_json_write", "active", `token=...${creds.accessToken.slice(-12)}`)
      log("sync_auth_json", { path: authPath, success: true })
    } catch (err) {
      log("sync_auth_json", {
        path: authPath,
        success: false,
        error: err instanceof Error ? err.message : String(err),
      })
      throw err
    }
  }
}

export const OAUTH_TOKEN_URL = "https://claude.ai/v1/oauth/token"
export const OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

/**
 * Parse a raw OAuth token response into ClaudeCredentials.
 * Returns null if the response is missing a valid access_token.
 * Defaults expires_in to 36000s (10h) to match observed Claude token lifetime.
 */
export function parseOAuthResponse(
  raw: string,
  currentRefreshToken: string,
  now: number = Date.now(),
): ClaudeCredentials | null {
  let data: {
    access_token?: string
    refresh_token?: string
    expires_in?: number
    error?: string
  }
  try {
    data = JSON.parse(raw)
  } catch {
    return null
  }

  if (!data.access_token) return null

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? currentRefreshToken,
    expiresAt: now + (data.expires_in ?? 36_000) * 1000,
  }
}

export function refreshViaOAuth(
  refreshToken: string,
): ClaudeCredentials | null {
  // Refresh is disabled in the plugin. A dedicated LaunchAgent service
  // handles token refresh to avoid multi-instance race conditions.
  log("refresh_disabled", { source: "oauth", reason: "delegated to refresh service" })
  return null
}

function refreshViaCli(): void {
  // Refresh is disabled in the plugin.
  log("refresh_disabled", { source: "cli", reason: "delegated to refresh service" })
}

export function refreshIfNeeded(
  account?: ClaudeAccount,
): ClaudeCredentials | null {
  const target = account ?? getActiveAccount()
  if (!target) return null

  const creds = target.credentials
  if (creds.expiresAt > Date.now() + 60_000) return creds

  // Token is expired or about to expire.
  // DO NOT refresh here — a dedicated LaunchAgent service handles refresh.
  // Just re-read from Keychain in case the service already refreshed.
  log("token_expired_rereading_keychain", {
    source: target.source,
    expiresAt: creds.expiresAt,
    expiresIn: creds.expiresAt - Date.now(),
  })

  const fromKeychain = refreshAccount(target.source)
  if (fromKeychain && fromKeychain.expiresAt > Date.now() + 60_000) {
    target.credentials = fromKeychain
    const h = ((fromKeychain.expiresAt - Date.now()) / 1000 / 3600).toFixed(1)
    audit("keychain_read_fresh", target.source, `+${h}h token=...${fromKeychain.accessToken.slice(-12)}`)
    log("token_refreshed_from_keychain", {
      source: target.source,
      expiresAt: fromKeychain.expiresAt,
    })
    return fromKeychain
  }

  log("credentials_expired", {
    source: target.source,
    message: "Token expired and no fresh token in Keychain. Waiting for refresh service.",
  })
  audit("credentials_expired", target.source, "no fresh token in Keychain")
  return null
}

/**
 * Returns the active account's credentials for auth.json sync purposes.
 * Unlike getCachedCredentials(), this does NOT trigger a refresh.
 * It returns the account's current in-memory credentials if they're still valid.
 * Returns null if no account or credentials are expired.
 */
export function getCredentialsForSync(): ClaudeCredentials | null {
  const account = getActiveAccount()
  if (!account) return null

  const creds = account.credentials
  if (creds.expiresAt > Date.now() + 60_000) {
    return creds
  }

  // Credentials are near expiry -- don't refresh here, let the per-request path handle it
  return null
}

export function getCachedCredentials(): ClaudeCredentials | null {
  const account = getActiveAccount()
  if (!account) return null

  const now = Date.now()
  const cached = accountCacheMap.get(account.source)
  if (
    cached &&
    now - cached.cachedAt < CREDENTIAL_CACHE_TTL_MS &&
    cached.creds.expiresAt > now + 60_000
  ) {
    log("cache_hit", {
      source: account.source,
      ttlRemaining: CREDENTIAL_CACHE_TTL_MS - (now - cached.cachedAt),
    })
    return cached.creds
  }

  log("cache_miss", {
    source: account.source,
    reason: cached ? "stale or expiring" : "empty",
  })

  // Before triggering a refresh, re-read from Keychain — another instance
  // may have already refreshed the token.
  const fromKeychain = refreshAccount(account.source)
  if (fromKeychain && fromKeychain.expiresAt > now + 60_000) {
    log("cache_refreshed_from_keychain", {
      source: account.source,
      expiresAt: fromKeychain.expiresAt,
    })
    account.credentials = fromKeychain
    accountCacheMap.set(account.source, { creds: fromKeychain, cachedAt: now })
    return fromKeychain
  }

  const fresh = refreshIfNeeded(account)
  if (!fresh) {
    log("credentials_unavailable", { source: account.source })
    accountCacheMap.delete(account.source)
    return null
  }

  accountCacheMap.set(account.source, { creds: fresh, cachedAt: now })
  return fresh
}
