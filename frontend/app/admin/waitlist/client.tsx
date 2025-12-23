"use client"

import Link from "next/link"
import { useEffect, useState } from "react"
import { ArrowLeft, Loader2, MailCheck, CheckCircle2, Archive, Edit3 } from "lucide-react"

import type { WaitlistRequest, WaitlistStatus } from "@/lib/waitlist"
import { WAITLIST_STATUSES } from "@/lib/waitlist"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"

type FetchState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; entries: WaitlistRequest[]; statuses: WaitlistStatus[] }

type EntryActionState = {
  saving: boolean
  error: string | null
}

const STATUS_LABEL: Record<WaitlistStatus, string> = {
  requested: "Requested",
  contacted: "Contacted",
  invited: "Invited",
  activated: "Activated",
  archived: "Archived",
}

const STATUS_TONE: Record<WaitlistStatus, string> = {
  requested: "border-blue-200 bg-blue-50 text-blue-700",
  contacted: "border-amber-200 bg-amber-50 text-amber-700",
  invited: "border-violet-200 bg-violet-50 text-violet-700",
  activated: "border-emerald-200 bg-emerald-50 text-emerald-700",
  archived: "border-neutral-200 bg-neutral-100 text-neutral-500",
}

const formatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
})

async function fetchWaitlist(status?: string) {
  const query = status ? `?status=${encodeURIComponent(status)}` : ""
  const response = await fetch(`/api/admin/waitlist${query}`, {
    method: "GET",
    headers: {
      "Cache-Control": "no-store",
    },
  })
  const payload = (await response.json().catch(() => ({}))) as {
    error?: string
    requests?: WaitlistRequest[]
    statuses?: WaitlistStatus[]
  }
  if (!response.ok) {
    throw new Error(payload.error ?? "Unable to load waitlist")
  }
  return {
    entries: payload.requests ?? [],
    statuses: payload.statuses ?? WAITLIST_STATUSES,
  }
}

async function updateWaitlistEntry(id: string, updates: Record<string, unknown>) {
  const response = await fetch(`/api/admin/waitlist/${id}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(updates),
  })
  const payload = (await response.json().catch(() => ({}))) as { error?: string; request?: WaitlistRequest }
  if (!response.ok) {
    throw new Error(payload.error ?? "Failed to update entry")
  }
  if (!payload.request) {
    throw new Error("Missing waitlist entry in response")
  }
  return payload.request
}

export default function AdminWaitlistClient() {
  const [fetchState, setFetchState] = useState<FetchState>({ status: "loading" })
  const [statusFilter, setStatusFilter] = useState<string>("")
  const [entryActions, setEntryActions] = useState<Record<string, EntryActionState>>({})

  useEffect(() => {
    let active = true
    setFetchState({ status: "loading" })
    fetchWaitlist(statusFilter)
      .then((data) => {
        if (!active) return
        setFetchState({ status: "ready", ...data })
      })
      .catch((error: Error) => {
        if (!active) return
        setFetchState({ status: "error", message: error.message })
      })
    return () => {
      active = false
    }
  }, [statusFilter])

  const entries = fetchState.status === "ready" ? fetchState.entries : []
  const statuses = fetchState.status === "ready" ? fetchState.statuses : WAITLIST_STATUSES

  const mutateEntry = async (entry: WaitlistRequest, updates: Record<string, unknown>) => {
    setEntryActions((prev) => ({
      ...prev,
      [entry.id]: { saving: true, error: null },
    }))
    try {
      const updated = await updateWaitlistEntry(entry.id, updates)
      setFetchState((prev) => {
        if (prev.status !== "ready") {
          return prev
        }
        return {
          ...prev,
          entries: prev.entries.map((item) => (item.id === entry.id ? updated : item)),
        }
      })
      setEntryActions((prev) => ({
        ...prev,
        [entry.id]: { saving: false, error: null },
      }))
    } catch (error) {
      setEntryActions((prev) => ({
        ...prev,
        [entry.id]: {
          saving: false,
          error: error instanceof Error ? error.message : "Failed to update entry",
        },
      }))
    }
  }

  const handleGrantAccess = async (entry: WaitlistRequest) => {
    setEntryActions((prev) => ({
      ...prev,
      [entry.id]: { saving: true, error: null },
    }))

    try {
      const response = await fetch(`/api/admin/waitlist/${entry.id}/activate`, {
        method: "POST",
      })
      const payload = (await response.json().catch(() => ({}))) as { request?: WaitlistRequest; error?: string }
      const updatedRequest = payload.request

      if (!response.ok || !updatedRequest) {
        throw new Error(payload.error ?? "Activation failed")
      }

      setFetchState((prev) => {
        if (prev.status !== "ready") {
          return prev
        }
        return {
          ...prev,
          entries: prev.entries.map((item) => (item.id === entry.id ? updatedRequest : item)),
        }
      })

      setEntryActions((prev) => ({
        ...prev,
        [entry.id]: { saving: false, error: null },
      }))
    } catch (error) {
      setEntryActions((prev) => ({
        ...prev,
        [entry.id]: {
          saving: false,
          error: error instanceof Error ? error.message : "Failed to grant access",
        },
      }))
    }
  }

  const handleMarkContacted = (entry: WaitlistRequest) =>
    mutateEntry(entry, { status: "contacted", mark_contacted: true })

  const handleArchive = (entry: WaitlistRequest) =>
    mutateEntry(entry, { status: "archived" })

  const handleEditNotes = (entry: WaitlistRequest) => {
    const next = window.prompt("Update notes for this workspace", entry.notes ?? "")
    if (next === null) {
      return
    }
    const trimmed = next.trim()
    mutateEntry(entry, { notes: trimmed.length > 0 ? trimmed : null })
  }

  const handleEditPriority = (entry: WaitlistRequest) => {
    const next = window.prompt("Priority (0-10)", entry.priority != null ? String(entry.priority) : "")
    if (next === null) {
      return
    }
    const trimmed = next.trim()
    if (!trimmed) {
      mutateEntry(entry, { priority: null })
      return
    }
    const numeric = Number(trimmed)
    if (Number.isNaN(numeric)) {
      window.alert("Priority must be a number between 0 and 10.")
      return
    }
    mutateEntry(entry, { priority: Math.min(Math.max(Math.round(numeric), 0), 10) })
  }

  return (
    <div className="min-h-screen bg-[#E2E2E2] px-6 pb-16 pt-10 text-[#08070B]">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
        <header className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <Button
              asChild
              variant="ghost"
              size="icon"
              className="h-10 w-10 rounded-full border border-[#1B0986]/40 bg-white/90 text-[#1B0986] shadow-sm transition hover:bg-[#1B0986] hover:text-white"
            >
              <Link href="/" aria-label="Back to landing page">
                <ArrowLeft className="h-5 w-5" />
              </Link>
            </Button>
            <div className="text-xs font-semibold uppercase tracking-[0.32em] text-[#1F1E28]/60">
              Early access
            </div>
          </div>
          <div className="flex flex-col justify-between gap-3 md:flex-row md:items-center">
            <div>
              <h1 className="text-3xl font-semibold tracking-tight">Umbra waitlist</h1>
              <p className="mt-2 text-sm leading-6 text-[#1F1E28]/80">
                Review incoming requests and hand out access when teams are ready. Grant access when you want to
                trigger an activation email, or mark contacted to keep your pipeline organised.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge className="rounded-full bg-[#1B0986] px-3 py-1 text-xs font-semibold text-white">
                {entries.length} total
              </Badge>
              {statuses.map((status) => (
                <Badge
                  key={status}
                  variant="outline"
                  className={`rounded-full border px-3 py-1 text-xs font-medium ${STATUS_TONE[status]}`}
                >
                  {STATUS_LABEL[status]}
                </Badge>
              ))}
            </div>
          </div>
        </header>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setStatusFilter("")}
            className={`rounded-full px-3.5 py-1.5 text-sm font-medium transition ${
              statusFilter === ""
                ? "bg-[#08070B] text-white shadow-[0_18px_40px_-28px_rgba(15,11,56,0.55)]"
                : "bg-white text-[#1F1E28]/80 shadow-sm"
            }`}
          >
            All stages
          </button>
          {statuses.map((status) => (
            <button
              key={status}
              type="button"
              onClick={() => setStatusFilter(status)}
              className={`rounded-full px-3.5 py-1.5 text-sm font-medium capitalize transition ${
                statusFilter === status
                  ? "bg-[#08070B] text-white shadow-[0_18px_40px_-28px_rgba(15,11,56,0.55)]"
                  : "bg-white text-[#1F1E28]/80 shadow-sm"
              }`}
            >
              {STATUS_LABEL[status]}
            </button>
          ))}
        </div>

        {fetchState.status === "loading" ? (
          <div className="flex h-48 items-center justify-center rounded-2xl border border-dashed border-[#d7d5eb] bg-white/70">
            <div className="flex items-center gap-3 text-sm font-medium text-[#1F1E28]/70">
              <Loader2 className="size-4 animate-spin text-[#1B0986]" />
              Loading waitlist…
            </div>
          </div>
        ) : null}

        {fetchState.status === "error" ? (
          <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {fetchState.message}
          </div>
        ) : null}

        {fetchState.status === "ready" && fetchState.entries.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-[#d7d5eb] bg-white px-6 py-16 text-center text-sm text-[#1F1E28]/70">
            No requests yet. Once teams register via the landing page, they’ll appear here.
          </div>
        ) : null}

        {fetchState.status === "ready" && fetchState.entries.length > 0 ? (
          <div className="overflow-hidden rounded-3xl border border-[#d7d5eb] bg-white shadow-[0_32px_90px_-72px_rgba(15,11,56,0.35)]">
            <table className="min-w-full divide-y divide-[#eceaf7]">
              <thead className="bg-[#F7F6FF]">
                <tr>
                  <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-[#6F6C90]">
                    Email
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-[#6F6C90]">
                    Company & focus
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-[#6F6C90]">
                    Submitted
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-[#6F6C90]">
                    Status
                  </th>
                  <th className="px-5 py-3 text-right text-xs font-semibold uppercase tracking-[0.2em] text-[#6F6C90]">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#eceaf7]">
                {entries.map((entry) => {
                  const actionState = entryActions[entry.id] ?? { saving: false, error: null }
                  return (
                    <tr key={entry.id} className="hover:bg-[#F8F6FF]">
                      <td className="whitespace-nowrap px-5 py-4 text-sm font-medium text-[#08070B]">
                        {entry.email}
                        <div className="mt-1 text-xs text-[#6F6C90]">
                          {entry.priority != null ? `Priority ${entry.priority}` : "Unprioritized"}
                        </div>
                      </td>
                      <td className="px-5 py-4 text-sm text-[#1F1E28]/80">
                        {entry.company ? <div className="font-medium text-[#08070B]">{entry.company}</div> : null}
                        <div className="text-xs text-[#6F6C90] whitespace-pre-wrap">
                          {entry.use_case ?? "—"}
                        </div>
                        {entry.notes ? (
                          <div className="mt-2 rounded-lg border border-[#eceaf7] bg-[#f9f8ff] px-3 py-2 text-xs text-[#5b5879]">
                            {entry.notes}
                          </div>
                        ) : null}
                      </td>
                      <td className="whitespace-nowrap px-5 py-4 text-sm text-[#1F1E28]/70">
                        <div>{formatter.format(new Date(entry.created_at))}</div>
                        <div className="text-xs text-[#6F6C90]">
                          {entry.last_contacted_at ? `Contacted ${formatter.format(new Date(entry.last_contacted_at))}` : "No contact yet"}
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <Badge
                          variant="outline"
                          className={`rounded-full border px-3 py-1 text-xs font-medium ${STATUS_TONE[entry.status]}`}
                        >
                          {STATUS_LABEL[entry.status]}
                        </Badge>
                        {entry.activation_sent_at ? (
                          <div className="mt-1 text-xs text-[#6F6C90]">
                            Activation sent {formatter.format(new Date(entry.activation_sent_at))}
                          </div>
                        ) : null}
                      </td>
                      <td className="whitespace-nowrap px-5 py-4 text-right">
                        <div className="flex flex-wrap justify-end gap-2">
                          <Button
                            size="sm"
                            className="inline-flex items-center gap-2 rounded-full bg-[#08070B] px-3.5 text-xs font-semibold text-white hover:bg-[#111015]"
                            disabled={actionState.saving}
                            onClick={() => handleGrantAccess(entry)}
                          >
                            Grant access
                            <CheckCircle2 className="size-3.5" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="inline-flex items-center gap-2 rounded-full border border-[#1B0986]/60 px-3.5 text-xs font-semibold text-[#1B0986]"
                            disabled={actionState.saving}
                            onClick={() => handleMarkContacted(entry)}
                          >
                            Mark contacted
                            <MailCheck className="size-3.5" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="inline-flex items-center gap-1 text-xs text-[#6F6C90]"
                            disabled={actionState.saving}
                            onClick={() => handleArchive(entry)}
                          >
                            <Archive className="size-3" />
                            Archive
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="inline-flex items-center gap-1 text-xs text-[#6F6C90]"
                            disabled={actionState.saving}
                            onClick={() => handleEditNotes(entry)}
                          >
                            <Edit3 className="size-3" />
                            Notes
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="inline-flex items-center gap-1 text-xs text-[#6F6C90]"
                            disabled={actionState.saving}
                            onClick={() => handleEditPriority(entry)}
                          >
                            <Edit3 className="size-3" />
                            Priority
                          </Button>
                        </div>
                        {actionState.error ? (
                          <div className="mt-2 text-xs text-red-600">{actionState.error}</div>
                        ) : null}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </div>
  )
}
