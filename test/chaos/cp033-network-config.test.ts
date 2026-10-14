// SPEC H4 / §11.6 T-01: known off-regtest configuration exits 5/network-lock
// on a mutating CLI before opening credentials or creating any database.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { jsonDocument, runCli, scratch, writeConfig } from '../helpers/cp016-cli.js';

function fixture(network:string) {
  const dir=scratch('t01-config-boundary'), database=join(dir,'never-created.db');
  const config=writeConfig(dir,{ database,nodes:[{ name:'offline',implementation:'lnd',url:'https://127.0.0.1:1',tlsCert:join(dir,'absent.cert'),credential:join(dir,'absent.macaroon'),expectedPubkey:'02'+'41'.repeat(32) }] });
  writeFileSync(config,readFileSync(config,'utf8').replace('expected_network: regtest',`expected_network: ${network}`));
  return {config,database};
}
for (const network of ['mainnet','testnet4','signet']) {
  it(`CP-033/B1 T-01 public execute refuses configured ${network} before missing database and credential files`,async()=>{
    const f=fixture(network),result=await runCli(['--json','actions','execute','prop_00000000000000000000000000','--require-regtest','--config',f.config]);
    expect(result.status).toBe(5);expect(jsonDocument(result)['error']).toMatchObject({ code:5,step:'network-lock' });
    expect(existsSync(f.database)).toBe(false);expect(existsSync(`${f.database}-wal`)).toBe(false);
  });
  it(`CP-033/B1 T-01 readonly configured ${network} retains an invalid configuration exit`,async()=>{
    const f=fixture(network),result=await runCli(['--json','liquidity','diagnose','--config',f.config]);
    expect(result.status).toBe(2);expect(jsonDocument(result)['error']).toMatchObject({ code:2,step:'config' });
    expect(existsSync(f.database)).toBe(false);
  });
}
it('CP-033/B1 T-01 malformed unknown configured network remains INVALID_INPUT rather than a valid off-regtest network',async()=>{
  const f=fixture('made-up-network'),result=await runCli(['--json','actions','execute','prop_00000000000000000000000000','--require-regtest','--config',f.config]);
  expect(result.status).toBe(2);expect(jsonDocument(result)['error']).toMatchObject({ code:2,step:'config' });expect(existsSync(f.database)).toBe(false);
});
