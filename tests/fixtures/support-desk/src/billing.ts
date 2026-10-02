// Scheduled jobs. See ../FIXTURE.md.
import { payments } from './runtime.js';

/**
 * @effects spend on #payments as #billing-sa -- "Nightly sweep retries failed refunds"
 */
export async function refundSweep() {
  return payments.retryFailed();
}

/**
 * @reaches #ci-runner to publish-package on #registry -- "npm publish in the release workflow"
 * @effects write on #registry -- "publish"
 */
export async function release() {
  return payments.noop();
}
