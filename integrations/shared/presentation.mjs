// Peer-authored content stays separate from the adapter's correlation metadata.
export const metadataMarker = 'Capsule event metadata:\n';
const titles = {
  message: 'Capsule request',
  reply: 'Capsule reply',
  task: 'Capsule task',
  task_cancel_requested: 'Capsule cancellation request',
  task_update: 'Capsule task update'
};

export function presentEvent(event) {
  return {
    text: (titles[event.meta.kind] ?? 'Capsule event') + '\n\n' + event.content,
    metadata: metadataMarker + JSON.stringify(event.meta)
  };
}
