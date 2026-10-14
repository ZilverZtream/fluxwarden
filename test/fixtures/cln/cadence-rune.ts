import { randomBytes, randomInt } from 'node:crypto';

// Disposable FORMAT-valid tokens provisioned only in the local golden server.
// They are not authenticated by any real node and contain no lab credentials.
// CLN v26.06.9, a2176589f235b63bc1a37e69362dfd6c925397e9:
//   ccan/ccan/rune/coding.c L76–108: | separates alternatives; & separates restrictions.
//   coding.c L265–293, L328–403: 32-byte state followed by UTF-8 restrictions,
//     encoded using the URL-safe alphabet (L9–14).
//   lightningd/runes.c L237–249: first empty-name restriction is the unique id.
//   doc/schemas/createrune.json L30–36, L130–175: published encoding and rate syntax.
// The restriction list below is SECURITY §3.2 with its bound set to 100000001 msat.
export function syntheticCadenceRune(): string {
  const id = randomInt(1, 99_999_999);
  const restrictions = `=${String(id)}`
    + '&method=getinfo|method=listpeerchannels|method=listchannels'
    + '|method=invoice|method=listinvoices|method=delinvoice'
    + '|method=getroutes|method^askrene-|method=sendpay|method=waitsendpay'
    + '|method=listsendpays|method=bkpr-listaccountevents'
    + '&method/sendpay|pnameamount_msat<100000001&rate=600';
  return Buffer.concat([randomBytes(32), Buffer.from(restrictions)]).toString('base64url');
}
