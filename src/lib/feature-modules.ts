import { CTI_TOOL_PROJECTS } from "@/lib/cti-tools"

export type FeatureModuleId = (typeof CTI_TOOL_PROJECTS)[number]["id"]

export const FEATURE_MODULE_IDS = CTI_TOOL_PROJECTS.map((p) => p.id) as FeatureModuleId[]

export type FeatureModuleMeta = (typeof CTI_TOOL_PROJECTS)[number]
