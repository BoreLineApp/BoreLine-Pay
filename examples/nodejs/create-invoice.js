// Create a BoreLine invoice from your backend and get a payment link.
//
// Run this on your SERVER only. The API key must never reach the browser.
//   BORELINE_API_KEY=your_secret_api_key node create-invoice.js
//
// Requires Node 18+ (built-in fetch).

const API_KEY = process.env.BORELINE_API_KEY;
if (!API_KEY) {
  console.error('Set BORELINE_API_KEY in your environment first.');
  process.exit(1);
}

async function createInvoice({ tier, email, months = 1, metadata } = {}) {
  const res = await fetch('https://api.borelinepay.uk/api/invoice', {
    method: 'POST',
    headers: {
      'X-API-Key': API_KEY,        // secret: server-side only
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tier, email, months, metadata }),
  });

  if (!res.ok) {
    throw new Error(`Invoice request failed: ${res.status} ${await res.text()}`);
  }
  return res.json();
}

// Example usage.
createInvoice({
  tier: 'starter',                 // a product key from your dashboard
  email: 'customer@example.com',   // optional label
  months: 1,                       // optional, defaults to 1
  metadata: { order_id: 'A-1042' } // optional, your own reference
})
  .then((invoice) => {
    console.log('Redirect the customer to:', invoice.invoice_url);
    console.log('Amount (sats):', invoice.amount_sats);
    console.log('Expires:', invoice.expires_at);
  })
  .catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
