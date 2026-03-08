/**
 * Stackmail server — entry point
 */

import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { loadConfig } from './types.js';
import { SqliteMessageStore } from './store.js';
import { PaymentService } from './payment.js';
import { createMailServer } from './app.js';

async function main(): Promise<void> {
  const config = loadConfig();
  await mkdir(dirname(config.dbFile), { recursive: true });

  const store = new SqliteMessageStore(config.dbFile);
  await store.init();
  console.log('stackmail: database ready');

  const paymentService = new PaymentService(config);
  const sfContractId = process.env.STACKMAIL_SF_CONTRACT_ID ?? '';

  const server = createMailServer(config, store, paymentService, sfContractId);

  server.listen(config.port, config.host, () => {
    console.log(`stackmail: listening on ${config.host}:${config.port}`);
  });
}

main().catch(err => {
  console.error('fatal:', err);
  process.exit(1);
});
