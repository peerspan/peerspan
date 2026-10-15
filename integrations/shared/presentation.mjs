// Peer-authored content stays separate from the adapter's correlation metadata.
export const metadataMarker = 'Peerspan event metadata:\n';
const titles = {
  hello: 'Peerspan readiness check',
  disconnected: 'Peerspan disconnected',
  message: 'Peerspan request',
  reply: 'Peerspan reply',
  task: 'Peerspan task',
  task_cancel_requested: 'Peerspan cancellation request',
  task_update: 'Peerspan task update'
};

export function presentEvent(event) {
  return {
    // An adopted task or redelivered item may continue earlier work.
    text:
      (titles[event.meta.kind] ?? 'Peerspan event') +
      (event.meta.adopted === true ? ' (adopted)' : event.meta.redelivered === true ? ' (redelivered)' : '') +
      '\n\n' +
      event.content,
    metadata: metadataMarker + JSON.stringify(event.meta)
  };
}
