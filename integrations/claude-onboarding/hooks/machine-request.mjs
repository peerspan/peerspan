// An existing-person pin identifies whom to ask, never key possession or consent.
import { quoted } from './project.mjs';
import { publicKey } from './invitation.mjs';
import { decodePublic } from './access.mjs';
const pinMeaning = 'This pin identifies whom to ask; it proves neither ownership nor the inviter\'s current authority.';

export function pinned(flow) {
  const pin = flow?.review?.invitation?.invitation?.expected_person_public_key;
  return publicKey(pin) && pin === flow.review.person_public_key;
}
export function publicReply(raw, machine) {
  if (machine) decodePublic(raw, 2 << 20);
  return raw;
}
export function identityLines(preview) {
  return ['Existing person public key: ' + quoted(preview.review.invitation.expected_person_public_key),
    'Original person key stays on the existing computer.',
    pinMeaning,
    'No original identity is read or created. No machine request has been prepared.'].join('\n');
}
export function outcomeLines(flow) {
  const o = flow.outcome;
  return o ? ['Request ID: ' + o.request_id, 'Published network ID: ' + o.network_id,
    'Published context ID: ' + o.context_id, 'Published person public key: ' + quoted(o.person_public_key)].join('\n') : '';
}
const limits = [
  'Original person key stays on the existing computer.',
  'Approval creates or reuses one request with a separate local device key and publishes it through ordinary transport.',
  'The actual requester host and device keys are reviewed in the later machine approval; no pre-publication key is asserted here.',
  'This publication grants no ownership, membership, machine powers or agent access.',
  'Approval on the existing computer is still required. Use Review machine requests on the existing computer.',
  'Publication and automatic-return availability do not prove delivery, current link state, permissions, transport or model receipt.',
].join('\n');
export function reviewLines(flow) {
  return ['Existing person public key: ' + quoted(flow.review.person_public_key), pinMeaning, limits].join('\n');
}
