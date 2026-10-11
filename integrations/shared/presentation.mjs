// Peer-authored content stays separate from the adapter's correlation metadata.
export const metadataMarker = 'Capsule event metadata:\n';
const titles = {
  hello: 'Capsule readiness check',
  disconnected: 'Capsule disconnected',
  message: 'Capsule request',
  reply: 'Capsule reply',
  task: 'Capsule task',
  task_cancel_requested: 'Capsule cancellation request',
  task_update: 'Capsule task update'
};

export function presentEvent(event) {
  return {
    // An adopted task or redelivered item may continue earlier work.
    text:
      (titles[event.meta.kind] ?? 'Capsule event') +
      (event.meta.adopted === true ? ' (adopted)' : event.meta.redelivered === true ? ' (redelivered)' : '') +
      '\n\n' +
      event.content,
    metadata: metadataMarker + JSON.stringify(event.meta)
  };
}
