// Verify a BoreLine webhook before acting on it.
//
// BoreLine signs every webhook so you can confirm it genuinely came from
// BoreLine and not an impostor. The pattern below is standard HMAC-SHA256:
// compute an HMAC of the RAW request body with your webhook secret, then
// compare it in constant time against the signature in the request headers.
//
// Your Webhook Secret is on the dashboard Settings page (separate from your API
// key). BoreLine sends the signature in the X-BoreLine-Sig header and the send
// time in X-BoreLine-Time.

const crypto = require('crypto');
const express = require('express');

const WEBHOOK_SECRET = process.env.BORELINE_WEBHOOK_SECRET; // "Webhook Secret" from the dashboard
const SIGNATURE_HEADER = 'x-boreline-sig';       // BoreLine sends the HMAC here
const TIMESTAMP_HEADER = 'x-boreline-time';      // unix seconds, reject if too old

const app = express();

// Capture the RAW body. Signatures are computed over exact bytes, so you must
// verify against the raw payload, not a re-serialized JSON object.
app.use(express.raw({ type: '*/*' }));

function isValidSignature(rawBody, providedSignature) {
  if (!WEBHOOK_SECRET || !providedSignature) return false;
  const expected = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  const a = Buffer.from(expected);
  const b = Buffer.from(providedSignature);
  // Lengths must match for timingSafeEqual, and matching guards against timing attacks.
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post('/webhooks/boreline', (req, res) => {
  const signature = req.get(SIGNATURE_HEADER);

  if (!isValidSignature(req.body, signature)) {
    console.warn('Rejected webhook: bad signature');
    return res.status(401).send('invalid signature');
  }

  const event = JSON.parse(req.body.toString('utf8'));
  // Now it is safe to act on the event, for example fulfil the order.
  console.log('Verified webhook:', event);
  // fulfilOrder(event) ...

  res.status(200).send('ok');
});

app.listen(3000, () => console.log('Listening for BoreLine webhooks on :3000'));
