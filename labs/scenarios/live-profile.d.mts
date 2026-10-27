export type Row = Record<string, unknown>;
export interface Binding { version: number; sourceCommit: string; ownerPath: string; ownerSha256: string; ownerId: string; project: string; manifestSha256: string }
export type Native = (service: string, args: string[]) => { exitCode: number | null; stdout: string; stderr: string };
export function readCurrentBinding(ownerPath: string, sourceCommit: string): Binding;
export function assertCurrentBinding(binding: Binding, ownerPath: string, sourceCommit: string): void;
export function independentPolicyJson(value: unknown): string;
export function independentPolicyHash(value: unknown): string;
export function reportedCaseName(assertion: unknown): string;
export function classifyFirstHop(attempt: unknown): 'accepted' | 'refused';
export function capturePlanner(input: { ownerPath: string; sourceCommit: string; evidenceRoot?: string; native?: Native }): { captureDir: string; receiptPath: string; referenceConflicts: Row[] };
export function assertPlannerCapture(captureDir: string, ownerPath: string, sourceCommit: string): Row;
export function retainDemoHandoff(input: { ownerPath: string; sourceCommit: string; bundle: string; actualT05Path: string; nativeHistoryPath: string; verificationPath: string; evidenceRoot?: string }): { handoffPath: string; runtimeManifest: { file: string; sha256: string } };
export function readRetainedDemoRuntime(handoff: Row): { owner: Row; runtime: Row };
export function frozenChaosPolicy(targets: Row): Row;
export function prepareChaos(input: { ownerPath: string; sourceRoot: string; sourceCommit: string; native?: Native }): Promise<{ planPath: string; policySha256: string; binding: Binding }>;
export function assertChaosPlan(plan: Row): void;
export function measureValidation(input: { sourceRoot: string; sourceSha256: string; invocation: string; evidenceRoot: string; selection: { file: string; fullName: string }[]; collectedAt: number; commands: { build: string[]; setup: string[]; run: { argv: string[]; report: string }[]; teardown: string[]; leak: string[] }; env?: NodeJS.ProcessEnv }): Promise<{ planPath: string }>;
import type { SpawnSyncOptionsWithStringEncoding, SpawnSyncReturns } from 'node:child_process';
export function setRunner(value: (file: string, args: string[], options: SpawnSyncOptionsWithStringEncoding) => SpawnSyncReturns<string>): void;
