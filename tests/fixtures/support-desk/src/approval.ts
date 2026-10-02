// The approval steps. See ../FIXTURE.md.
import { queue } from './runtime.js';

/**
 * @gates #payments by #support-human for issue-refund -- "requireApproval() parks the refund until a human approves it"
 */
export async function requireApproval(orderId: string) {
  return queue.waitFor(orderId);
}

/**
 * @gates #outbox by #support-human -- "Every outbound email waits in the review queue"
 * @effects notify on #outbox -- "sendEmail, after review"
 */
export async function sendEmail(to: string, body: string) {
  await queue.waitFor(to);
  return queue.send(to, body);
}
