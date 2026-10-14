import type { LabPort, FaultPort } from '../../../src/commands/lab.js';
import type { EvidenceNode } from '../../../src/evidence/bundle.js';
export function readDemoEvidence(options: {
  planPath: string; configPath: string; recordedNodes: readonly EvidenceNode[];
  recovered: readonly { id: string; hash: string; nodePubkey: string; status: string }[];
}): Promise<{ images: Record<string, string>; scenarios: {
  caseId: string; injection: string; exit: number; status: string; paymentHash: string; sendCount: number;
  executionId: string; recoveredStatus: string; pass: boolean; assertions: string[];
}[] }>;
export function createRuntimeLab(options: { planPath: string; configPath: string; signal: AbortSignal }): Promise<{
  lab: LabPort; faults: FaultPort;
  preparation: {
    identity(): Promise<{ network: string }>;
    channels(): Promise<{ channel2ReceivableMsat: bigint; channel5ReceivableMsat: bigint }>;
    checkout: LabPort['checkout'];
    channelKeys(): Promise<{ channel2: string; channel5: string }>;
    record(name: string, document: Record<string, unknown>): void;
  };
  up(seed: string | null): Promise<Record<string, unknown>>;
  down(): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}>;
