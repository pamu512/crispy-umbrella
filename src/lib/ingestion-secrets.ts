import { invoke } from "@tauri-apps/api/core"

/** Matches `IngestionSecretSlotMeta` from the host (`#[serde(rename_all = "camelCase")]`). */
export type IngestionSecretSlotMeta = {
  service: string
  label: string
  description: string
  envFallback: string | null
}

export async function listIngestionSecretSlots(): Promise<IngestionSecretSlotMeta[]> {
  return invoke<IngestionSecretSlotMeta[]>("list_ingestion_secret_slots")
}

/** Key = keyring service id (e.g. `intelx_api_key`). */
export async function getIngestionSecretStatuses(): Promise<Record<string, boolean>> {
  return invoke<Record<string, boolean>>("get_ingestion_secret_statuses")
}

export async function saveIngestionSecret(service: string, secret: string): Promise<void> {
  return invoke<void>("save_ingestion_secret", { service, secret })
}

export async function clearIngestionSecret(service: string): Promise<void> {
  return invoke<void>("clear_ingestion_secret", { service })
}
