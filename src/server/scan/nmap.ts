/**
 * Controlled nmap adapter.
 *
 *  - Enabled only when SCAN_ENABLE_NMAP=1 AND an `nmap` binary responds to --version.
 *  - Spawned without a shell, from a fixed argument set built here; nothing user-supplied
 *    reaches the command line except the already-validated target and port list.
 *  - TCP connect scans (-sT) only: no SYN/stealth, idle, decoy, spoofing, fragmentation,
 *    timing above -T4, OS fingerprinting or NSE scripts.
 */
import { spawn } from "node:child_process";
import type { HostResult, PortResult } from "./checks.ts";
import { compactPorts, type ScanPlan } from "./policy.ts";

const BIN = process.env.NMAP_PATH || "nmap";
let cached: { at: number; status: { available: boolean; version: string | null; reason: string } } | null = null;

export async function nmapStatus() {
  if (process.env.SCAN_ENABLE_NMAP !== "1")
    return { available: false, version: null, reason: "Disabled. Set SCAN_ENABLE_NMAP=1 only on a host that is authorized to scan the allowlisted networks." };
  if (cached && Date.now() - cached.at < 60_000) return cached.status;
  const status = await new Promise<{ available: boolean; version: string | null; reason: string }>((resolve) => {
    let out = "";
    const p = spawn(BIN, ["--version"], { shell: false, windowsHide: true });
    const t = setTimeout(() => { p.kill(); resolve({ available: false, version: null, reason: "nmap --version timed out" }); }, 5000);
    p.stdout.on("data", (d) => (out += d));
    p.on("error", () => { clearTimeout(t); resolve({ available: false, version: null, reason: `nmap binary not found (${BIN})` }); });
    p.on("close", (code) => {
      clearTimeout(t);
      const v = /Nmap version (\S+)/.exec(out)?.[1] ?? null;
      resolve(code === 0 && v ? { available: true, version: v, reason: "ready" } : { available: false, version: null, reason: `nmap exited with code ${code}` });
    });
  });
  cached = { at: Date.now(), status };
  return status;
}

/** The complete argument vector for a validated plan. */
export function nmapArgs(plan: ScanPlan): string[] {
  const base = ["-n", "-oX", "-", "--stats-every", "5s", `-T${plan.intensity}`, "--max-retries", "2", "--host-timeout", `${plan.timeoutSec}s`];
  const ports = compactPorts(plan.portList);
  const byType: Record<ScanPlan["type"], string[]> = {
    host_discovery: ["-sn"],
    network_discovery: ["-sT", "--open", "-p", ports],
    tcp: ["-sT", "--open", "-p", ports],
    udp: ["-sU", "--open", "-p", ports],
    service: ["-sT", "-sV", "--version-light", "--open", "-p", ports],
    vuln_basic: ["-sT", "-sV", "--version-light", "--open", "-p", ports],
  };
  return [...base, ...byType[plan.type], plan.targetInfo.network];
}

const attr = (tag: string, name: string) => new RegExp(`${name}="([^"]*)"`).exec(tag)?.[1] ?? null;
const unescape = (s: string | null) => s?.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&") ?? null;

/** Minimal parser for nmap -oX output (hosts, addresses, hostnames, ports, services). */
export function parseNmapXml(xml: string): HostResult[] {
  const hosts: HostResult[] = [];
  for (const m of xml.matchAll(/<host\b[\s\S]*?<\/host>/g)) {
    const block = m[0];
    const addr = /<address\b[^>]*addrtype="ipv4"[^>]*>/.exec(block)?.[0];
    const ip = addr ? attr(addr, "addr") : null;
    if (!ip) continue;
    const status = /<status\b[^>]*>/.exec(block)?.[0];
    const hn = /<hostname\b[^>]*>/.exec(block)?.[0];
    const ports: PortResult[] = [];
    for (const pm of block.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/g)) {
      const state = /<state\b[^>]*>/.exec(pm[2])?.[0];
      const svc = /<service\b[^>]*>/.exec(pm[2])?.[0];
      const st = (state && attr(state, "state")) ?? "unknown";
      ports.push({
        port: Number(attr(pm[1], "portid")), proto: attr(pm[1], "protocol") === "udp" ? "udp" : "tcp",
        state: st === "open" ? "open" : st === "closed" ? "closed" : "filtered",
        service: svc ? unescape(attr(svc, "name")) : null, product: svc ? unescape(attr(svc, "product")) : null, version: svc ? unescape(attr(svc, "version")) : null,
      });
    }
    hosts.push({ ip, hostname: hn ? unescape(attr(hn, "name")) : null, state: status && attr(status, "state") === "up" ? "up" : "down", os: null, ports });
  }
  return hosts;
}

export function runNmap(plan: ScanPlan, onProgress: (pct: number) => void, signal: AbortSignal): Promise<{ hosts: HostResult[]; args: string[] }> {
  const args = nmapArgs(plan);
  return new Promise((resolve, reject) => {
    const p = spawn(BIN, args, { shell: false, windowsHide: true });
    let out = "", err = "";
    const hard = setTimeout(() => p.kill("SIGKILL"), (plan.timeoutSec + 30) * 1000);
    signal.addEventListener("abort", () => p.kill("SIGTERM"));
    p.stdout.on("data", (d) => {
      out += d;
      if (out.length > 20_000_000) p.kill("SIGKILL");
      const pct = [...String(d).matchAll(/percent="([\d.]+)"/g)].pop()?.[1];
      if (pct) onProgress(Math.min(99, Number(pct)));
    });
    p.stderr.on("data", (d) => (err = (err + d).slice(-2000)));
    p.on("error", (e) => { clearTimeout(hard); reject(e); });
    p.on("close", (code) => {
      clearTimeout(hard);
      if (signal.aborted) return reject(new Error("cancelled"));
      if (code !== 0) return reject(new Error(`nmap exited with code ${code}: ${err.trim().split("\n").pop() ?? ""}`));
      resolve({ hosts: parseNmapXml(out), args });
    });
  });
}
