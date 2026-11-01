/**
 * Email-domain ownership proof for SAML discovery.
 *
 * An organisation claims a domain, publishes one DNS TXT record, and
 * asks the API to check it. Until the check succeeds the domain is not
 * used by `GET /api/v1/auth/saml/discover`, so a workspace owner cannot
 * point another company's sign-in attempts at their own identity
 * provider merely by typing that company's domain into a SAML config.
 *
 * Record: `_proofvisor-challenge.<domain>` TXT `proofvisor-domain-verification=<token>`.
 *
 * Tests run without public DNS. When NODE_ENV is not "production" and
 * `PV_TEST_DNS_TXT_FILE` names a JSON file of the shape
 * `{ "<record name>": ["<txt value>", ...] }`, the file answers the
 * lookup instead of the resolver. Production ignores the variable.
 */
import { promises as dns } from "node:dns";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { env } from "../env.js";

export const CHALLENGE_LABEL = "_proofvisor-challenge";
export const TXT_PREFIX = "proofvisor-domain-verification=";

// RFC 1035 hostname labels; at least two labels; lowercase after NFC.
const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

/** Lowercase, NFC-normalised domain, or null when it is not a hostname. */
export function normaliseDomain(raw: string): string | null {
  const d = raw.trim().toLowerCase().normalize("NFC").replace(/\.$/, "");
  return DOMAIN_RE.test(d) ? d : null;
}

export function newChallengeToken(): string {
  return randomBytes(24).toString("base64url");
}

export function challengeRecordName(domain: string): string {
  return `${CHALLENGE_LABEL}.${domain}`;
}

export function challengeRecordValue(token: string): string {
  return TXT_PREFIX + token;
}

async function lookupTxt(name: string): Promise<string[]> {
  const fixture = process.env.PV_TEST_DNS_TXT_FILE;
  if (fixture && env.NODE_ENV !== "production") {
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(await readFile(fixture, "utf8"));
    } catch {
      return [];
    }
    const entry = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>)[name] : undefined;
    return Array.isArray(entry) ? entry.filter((v): v is string => typeof v === "string") : [];
  }
  try {
    const records = await dns.resolveTxt(name);
    // Each TXT record arrives as its character-string chunks.
    return records.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

/** True when the challenge TXT record for `domain` carries `token`. */
export async function challengeIsPublished(domain: string, token: string): Promise<boolean> {
  const expected = challengeRecordValue(token);
  const values = await lookupTxt(challengeRecordName(domain));
  return values.some((value) => value.trim() === expected);
}
