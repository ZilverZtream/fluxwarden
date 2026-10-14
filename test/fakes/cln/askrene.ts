// askrene layer commands of Core Lightning v26.06.9 with the plugin's in-memory layer table, so a test
// can see which layers exist after an assessment. Behaviour ids and sources are in fake-cln.ts.
import type { ClnContext, ClnHandler, FakeCln } from './fake-cln.js';

export interface LayerState {
  /** Layer name → disabled nodes and channel updates, as askrene-listlayers reports them. */
  readonly layers: Map<string, { disabledNodes: string[]; channelUpdates: { short_channel_id_dir: string; enabled?: boolean }[] }>;
}

function layerJson(name: string, layer: LayerState['layers'] extends Map<string, infer V> ? V : never): Record<string, unknown> {
  return {
    layer: name, persistent: false, disabled_nodes: layer.disabledNodes, disabled_channels: [], created_channels: [],
    channel_updates: layer.channelUpdates, constraints: [], biases: [], node_biases: [],
  };
}

/** Handlers for askrene-create-layer, -disable-node, -update-channel, -remove-layer and -listlayers over one shared state. */
export function askrene(state: LayerState = { layers: new Map() }, overrides: Partial<Record<string, ClnHandler>> = {}): { state: LayerState; methods: Record<string, ClnHandler> } {
  const known = (context: ClnContext, cln: FakeCln): string | null => {
    const name = context.params['layer'];
    if (typeof name === 'string' && state.layers.has(name)) return name;
    cln.rpcError(context, 'askrene-unknown-layer', -32602, 'layer: Unknown layer');
    return null;
  };
  const methods: Record<string, ClnHandler> = {
    'askrene-create-layer': (context, cln) => {
      const name = context.params['layer'];
      if (typeof name !== 'string') { cln.rpcError(context, 'askrene-unknown-layer', -32602, 'layer: should be a string'); return; }
      if (state.layers.has(name)) { cln.rpcError(context, 'askrene-layer-exists', -32602, 'Layer already exists'); return; }
      const layer = { disabledNodes: [], channelUpdates: [] };
      state.layers.set(name, layer);
      cln.result(context, 'askrene-create-layer', { layers: [layerJson(name, layer)] });
    },
    'askrene-disable-node': (context, cln) => {
      const name = known(context, cln);
      if (name === null) return;
      state.layers.get(name)?.disabledNodes.push(String(context.params['node']));
      cln.result(context, 'askrene-disable-node', {});
    },
    'askrene-update-channel': (context, cln) => {
      const name = known(context, cln);
      if (name === null) return;
      const update: { short_channel_id_dir: string; enabled?: boolean } = { short_channel_id_dir: String(context.params['short_channel_id_dir']) };
      if (typeof context.params['enabled'] === 'boolean') update.enabled = context.params['enabled'];
      state.layers.get(name)?.channelUpdates.push(update);
      cln.result(context, 'askrene-update-channel', {});
    },
    'askrene-remove-layer': (context, cln) => {
      const name = known(context, cln);
      if (name === null) return;
      state.layers.delete(name);
      cln.result(context, 'askrene-remove-layer', {});
    },
    'askrene-listlayers': (context, cln) => {
      cln.result(context, 'askrene-listlayers', { layers: [...state.layers.entries()].map(([name, layer]) => layerJson(name, layer)) });
    },
    ...overrides,
  };
  return { state, methods };
}
