"use client";

import { Siren, UserPlus } from "lucide-react";
import { useEffect, useState } from "react";
import { Button, Field, Input, Modal, Select, SevBadge, Textarea, useToast } from "./ui";
import { api } from "@/lib/client";
import type { Alert } from "@/lib/types";

export const useAnalysts = () => {
  const [a, setA] = useState<string[]>([]);
  useEffect(() => { api<{ analysts: string[] }>("/api/meta").then((m) => setA(m.analysts)).catch(() => {}); }, []);
  return a;
};

export function CreateIncident({ ids, onClose, onCreated, analysts, alerts }: { ids: string[] | null; onClose: () => void; onCreated: (id: string) => void; analysts: string[]; alerts: Alert[] }) {
  const toast = useToast();
  const chosen = alerts.filter((a) => ids?.includes(a.id));
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [assignee, setAssignee] = useState("");
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    if (!ids) return;
    const first = alerts.find((a) => ids.includes(a.id));
    setTitle(first ? `${first.ruleName} against ${first.asset ?? first.targetIp}${ids.length > 1 ? ` (+${ids.length - 1} related)` : ""}` : "");
    setDescription(first ? `Opened from ${ids.length} alert(s). Primary source ${first.sourceIp}.` : "");
  }, [ids, alerts]);
  const submit = async () => {
    setSaving(true);
    try {
      const inc = await api<{ id: string }>("/api/incidents", { method: "POST", json: { title, description, alertIds: ids ?? [], assignee: assignee || null } });
      toast({ tone: "success", title: `Incident ${inc.id} created` });
      onCreated(inc.id);
    } catch (e) { toast({ tone: "error", title: "Could not create incident", body: (e as Error).message }); }
    finally { setSaving(false); }
  };
  return (
    <Modal open={!!ids} onClose={onClose} title="Create incident" width={560}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={saving} disabled={title.trim().length < 3} onClick={submit}><Siren className="h-3.5 w-3.5" />Create incident</Button></>}>
      <div className="space-y-3">
        <Field label="Title"><Input value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
        <Field label="Description"><Textarea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
        <Field label="Assign to"><Select value={assignee} onChange={(e) => setAssignee(e.target.value)}><option value="">Unassigned</option>{analysts.map((a) => <option key={a}>{a}</option>)}</Select></Field>
        {!!ids?.length && <div>
          <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-3">Linked alerts ({ids.length}) — new alerts move to Escalated</div>
          <ul className="space-y-1">{(chosen.length ? chosen : ids.map((id) => ({ id }) as Alert)).map((a) => (
            <li key={a.id} className="flex items-center gap-2 text-[12px]">{a.severity && <SevBadge s={a.severity} />}<span className="font-mono text-ink-3">{a.id}</span><span className="truncate">{a.title}</span></li>
          ))}</ul>
        </div>}
        <p className="flex items-center gap-1.5 text-[11.5px] text-ink-3"><UserPlus className="h-3.5 w-3.5" />The timeline is built automatically from the alerts and their contributing events.</p>
      </div>
    </Modal>
  );
}
