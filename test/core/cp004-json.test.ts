import { expect, it } from 'vitest';
import { loadCore, type Errors, type Readers } from '../helpers/cp004-reference.js';

it('CP-004/B3 node amounts accept safe numbers and msat strings while identifiers keep uint64 precision', async () => {
  const reader = await loadCore<Readers>('json');
  const errors = await loadCore<Errors>('errors');
  const unsafeJsonNumber = Number('9007199254740993');
  for (const [value, expected] of [['1000', 1000n], [1000, 1000n], ['1000msat', 1000n], ['0msat', 0n], ['9223372036854775807msat', 9223372036854775807n], ['9007199254740993', 9007199254740993n]] as const) {
    expect(reader.integer({ amount: value }, 'amount')).toBe(expected);
  }
  for (const value of [unsafeJsonNumber, '-1', '9223372036854775808', true, {}, [], '1.5', '1e3', '+1', '01', 'msat', '1000MSAT', '1000 msat', ' 1000', '1000msat\n']) {
    expect(() => reader.integer({ amount: value }, 'amount'), 'invalid node amount').toThrow(errors.ProtocolError);
  }
  expect(reader.identifier({ id: '18446744073709551615' }, 'id')).toBe('18446744073709551615');
  expect(reader.identifier({ id: '9223372036854775808' }, 'id')).toBe('9223372036854775808');
  for (const value of ['18446744073709551616', '-1', unsafeJsonNumber, true]) {
    expect(() => reader.identifier({ id: value }, 'id')).toThrow(errors.ProtocolError);
  }
  expect(reader.integer({}, 'optional')).toBe(0n);
  expect(reader.string({}, 'optional')).toBe('');
  expect(reader.boolean({}, 'optional')).toBe(false);
});

it('CP-004/B9 extracted readers preserve defaults enum mapping and strict container types', async () => {
  const reader = await loadCore<Readers>('json');
  const errors = await loadCore<Errors>('errors');
  const source = { name: 'peer', active: true, items: [1, '2'], nested: { id: '7' } };
  expect(reader.asObject(source, 'answer')).toEqual(source);
  expect(reader.string(source, 'name')).toBe('peer');
  expect(reader.boolean(source, 'active')).toBe(true);
  expect(reader.array(source, 'items')).toEqual([1, '2']);
  expect(reader.optionalObject(source, 'nested')).toEqual({ id: '7' });
  expect(reader.optionalObject({}, 'optional')).toBeUndefined();
  expect(reader.array({}, 'optional')).toEqual([]);
  expect(reader.enumName({}, 'status', ['UNKNOWN', 'OK'])).toBe('UNKNOWN');
  expect(reader.enumName({ status: 1 }, 'status', ['UNKNOWN', 'OK'])).toBe('OK');
  expect(reader.enumName({ status: 'FUTURE' }, 'status', ['UNKNOWN', 'OK'])).toBe('FUTURE');
  expect(reader.smallInteger({ count: '9007199254740991' }, 'count')).toBe(9007199254740991);
  expect(() => reader.smallInteger({ count: '9007199254740992' }, 'count')).toThrow(errors.ProtocolError);
  expect(() => reader.checkedNonNegative(-1n, 'amount')).toThrow(errors.ProtocolError);
  expect(() => reader.checkedNonNegative(9223372036854775808n, 'amount')).toThrow(errors.ProtocolError);
  for (const value of [null, [], 1, 'object']) expect(() => reader.asObject(value, 'answer')).toThrow(errors.ProtocolError);
  expect(() => reader.string({ field: false }, 'field')).toThrow(errors.ProtocolError);
  expect(() => reader.boolean({ field: 'false' }, 'field')).toThrow(errors.ProtocolError);
  expect(() => reader.array({ field: {} }, 'field')).toThrow(errors.ProtocolError);
  expect(() => reader.optionalObject({ field: [] }, 'field')).toThrow(errors.ProtocolError);
  expect(() => reader.enumName({ status: 2 }, 'status', ['UNKNOWN', 'OK'])).toThrow(errors.ProtocolError);
});

it('CP-004/B3 signed zero text is not a canonical node amount or identifier', async () => {
  const reader = await loadCore<Readers>('json');
  const errors = await loadCore<Errors>('errors');
  // Node uint64 values are unsigned decimal text; "-0" never comes from a conforming node.
  for (const value of ['-0', '-0msat']) expect(() => reader.integer({ amount: value }, 'amount'), value).toThrow(errors.ProtocolError);
  expect(() => reader.identifier({ id: '-0' }, 'id')).toThrow(errors.ProtocolError);
  expect(reader.integer({ amount: '0' }, 'amount')).toBe(0n);
  expect(reader.identifier({ id: '0' }, 'id')).toBe('0');
});
