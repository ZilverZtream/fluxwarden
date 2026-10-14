import { expect, it } from 'vitest';
import { asRecord, readJson, readText } from '../helpers/cli.js';
import { parseYaml } from '../helpers/yaml.js';

// Image and service expectations are from SPEC 11.1 and ARCHITECTURE 10.1.
const services = ['bitcoind', 'lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m', 'toxiproxy'];
const bitcoinPin = 'lightninglabs/bitcoin-core:31.1@sha256:86e15e4348869a86343aacbbd1aff38e96cffddd87b61644694b1e1358d737cd';
const lndPin = 'lightninglabs/lnd:v0.21.4-beta@sha256:04d06edcc0f6e99a5e797ea34959f330add222226f840cd86afbc31f8f29627d';
const clnPin = 'elementsproject/lightningd:v26.06.9@sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577';
const toxiproxyPin = 'ghcr.io/shopify/toxiproxy:2.12.0@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e';

function composition(): Record<string, unknown> {
  return asRecord(asRecord(parseYaml(readText('labs/docker/docker-compose.yml')), 'compose')['services'], 'services');
}

it('CP-006/B6 seven services use release digests and published ports bind only loopback', () => {
  const actual = composition();
  expect(Object.keys(actual).sort()).toEqual([...services].sort());
  for (const name of services) {
    const service = asRecord(actual[name], name);
    const image = service['image'];
    expect(typeof image === 'string' && /^[^\s$<>]+@sha256:[a-f0-9]{64}$/.test(image), `${name} exact resolved digest`).toBe(true);
    if (name === 'bitcoind') expect(image).toBe(bitcoinPin);
    if (name.startsWith('lnd-')) expect(image).toBe(lndPin);
    if (name.startsWith('cln-')) expect(image, `${name} independently measured registry index`).toBe(clnPin);
    if (name === 'toxiproxy') expect(image, `${name} independently measured registry index`).toBe(toxiproxyPin);
    for (const binding of (service['ports'] ?? []) as unknown[]) {
      if (typeof binding === 'string') expect(binding.startsWith('127.0.0.1:'), `${name} loopback binding`).toBe(true);
      else expect(asRecord(binding, 'port')['host_ip'], `${name} loopback binding`).toBe('127.0.0.1');
    }
    const health = asRecord(service['healthcheck'], `${name} healthcheck`);
    expect(health['disable']).not.toBe(true);
    expect(health['test'], `${name} observed health command`).toBeTruthy();
    const limits = service['deploy'] === undefined ? service : asRecord(asRecord(asRecord(service['deploy'], 'deploy')['resources'], 'resources')['limits'], 'limits');
    const cpu = limits['cpus'];
    expect(typeof cpu === 'string' || typeof cpu === 'number', `${name} concrete cpu allocation`).toBe(true);
    expect(Number(cpu), `${name} positive finite cpu allocation`).toBeGreaterThan(0);
    expect(Number.isFinite(Number(cpu)), `${name} bounded cpu allocation`).toBe(true);
    expect(String(limits['memory'] ?? limits['mem_limit']), `${name} concrete memory allocation`).toMatch(/^[1-9]\d*(?:\.\d+)?(?:[kmgt]i?b?|b)?$/i);
  }
});

it('CP-006/B6 node flags enable pinned regtest gossip without removed options', () => {
  const actual = composition();
  for (const name of services.filter(service => service.startsWith('lnd-') || service.startsWith('cln-'))) {
    const command = asRecord(actual[name], name)['command'];
    const args = Array.isArray(command) ? command.map(String) : String(command).split(/\s+/);
    expect(args.some(arg => /^--tor\.v2(?:=|$)/.test(arg)), `${name} removed flag`).toBe(false);
    const required = name.startsWith('lnd-')
      ? ['--bitcoin.regtest', '--bitcoin.node=bitcoind', '--noseedbackup', '--trickledelay=1000', '--maxpendingchannels=10', `--tlsextradomain=${name}`]
      : ['--network=regtest', '--developer', '--dev-fast-gossip'];
    for (const flag of required) expect(args, `${name} ${flag}`).toContain(flag);
    if (name === 'cln-m') {
      expect(args).toContain('--clnrest-host=0.0.0.0');
      expect(args.some(arg => /^--clnrest-port=\d+$/.test(arg)), 'CLN merchant REST port').toBe(true);
    }
  }
});

it('CP-006/B6 developer commands dispatch the lab entry with explicit up and down actions', () => {
  const scripts = asRecord(asRecord(readJson('package.json'), 'package')['scripts'], 'scripts');
  expect(scripts['lab:up']).toBe('node labs/docker/lab.mjs up');
  expect(scripts['lab:down']).toBe('node labs/docker/lab.mjs down');
});

it('CP-006/B6 five channels and directional fees match canonical fixed topology amounts', () => {
  const actual = asRecord(readJson('labs/topology.json'), 'topology');
  expect(actual).toEqual({
    channels: [
      { id: '1', from: 'lnd-p', to: 'lnd-r', capacity_msat: '5000000000', push_msat: '1000000000' },
      { id: '2', from: 'lnd-r', to: 'cln-m', capacity_msat: '5000000000', push_msat: '1250000000' },
      { id: '3', from: 'lnd-r', to: 'cln-r', capacity_msat: '5000000000', push_msat: '2500000000' },
      { id: '4', from: 'cln-p', to: 'cln-r', capacity_msat: '5000000000', push_msat: '1000000000' },
      { id: '5', from: 'cln-r', to: 'cln-m', capacity_msat: '5000000000', push_msat: '1250000000' },
    ],
    policies: { base_fee_msat: '1000', fee_rate_ppm: '1000', lnd_cltv_delta: '80', cln_cltv_delta: '34' },
  });
});
