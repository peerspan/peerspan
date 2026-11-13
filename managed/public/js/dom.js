// Small DOM helpers. All dynamic text reaches the page as text nodes, never as HTML.

const SVG_NS = 'http://www.w3.org/2000/svg';

const ICONS = {
  overview: ['M3 3h7v7H3z', 'M14 3h7v7h-7z', 'M14 14h7v7h-7z', 'M3 14h7v7H3z'],
  workflows: ['M17 1l4 4-4 4', 'M3 11V9a4 4 0 0 1 4-4h14', 'M7 23l-4-4 4-4', 'M21 13v2a4 4 0 0 1-4 4H3'],
  runs: ['M8 6h13', 'M8 12h13', 'M8 18h13', 'M3 6h.01', 'M3 12h.01', 'M3 18h.01'],
  workers: ['M4 4h16v16H4z', 'M9 9h6v6H9z', 'M9 1v3', 'M15 1v3', 'M9 20v3', 'M15 20v3', 'M20 9h3', 'M20 14h3', 'M1 9h3', 'M1 14h3'],
  activity: ['M22 12h-4l-3 9L9 3l-3 9H2'],
  plus: ['M12 5v14', 'M5 12h14'],
  pause: ['M6 4h4v16H6z', 'M14 4h4v16h-4z'],
  play: ['M5 3l14 9-14 9V3z'],
  zap: ['M13 2L3 14h9l-1 8 10-12h-9l1-8z'],
  alert: ['M10.290 3.860L1.820 18a2 2 0 0 0 1.710 3h16.940a2 2 0 0 0 1.710-3L13.710 3.860a2 2 0 0 0-3.420 0z', 'M12 9v4', 'M12 17h.01'],
  info: ['M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z', 'M12 16v-4', 'M12 8h.01'],
  check: ['M20 6L9 17l-5-5'],
  close: ['M18 6L6 18', 'M6 6l12 12'],
  copy: ['M9 9h13v13H9z', 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1'],
  edit: ['M12 20h9', 'M16.500 3.500a2.120 2.120 0 0 1 3 3L7 19l-4 1 1-4L16.500 3.500z'],
  archive: ['M21 8v13H3V8', 'M1 3h22v5H1z', 'M10 12h4'],
  eye: ['M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'],
  stop: ['M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z', 'M9 9h6v6H9z']
};

export function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  const attributes = {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    'stroke-width': '2',
    'stroke-linecap': 'round',
    'stroke-linejoin': 'round',
    'aria-hidden': 'true'
  };
  for (const [key, value] of Object.entries(attributes)) svg.setAttribute(key, value);
  for (const d of ICONS[name] ?? []) {
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

/**
 * h('a.row', {href: '#/'}, 'text', child): creates an element. `tag` may carry
 * classes; attributes starting with "on" are listeners; null, undefined and
 * false children and attributes are skipped; strings become text nodes.
 */
export function h(tag, attributes, ...children) {
  const [name, ...classes] = tag.split('.');
  const element = document.createElement(name || 'div');
  if (classes.length) element.className = classes.join(' ');
  for (const [key, value] of Object.entries(attributes ?? {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') element.className = [element.className, value].filter(Boolean).join(' ');
    else if (key.startsWith('on')) element.addEventListener(key.slice(2), value);
    else element.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    element.append(child);
  }
  return element;
}

// ----- time ----------------------------------------------------------------------

function relativeText(iso) {
  const seconds = Math.round((Date.now() - Date.parse(iso)) / 1000);
  const ahead = seconds < 0;
  const value = Math.abs(seconds);
  const amount = value < 45 ? null
    : value < 3600 ? `${Math.max(1, Math.round(value / 60))}m`
      : value < 86_400 ? `${Math.round(value / 3600)}h`
        : `${Math.round(value / 86_400)}d`;
  if (amount === null) return ahead ? 'in a moment' : 'just now';
  return ahead ? `in ${amount}` : `${amount} ago`;
}

export function absoluteTime(iso) {
  return new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' });
}

/** A <time> that shows a relative time, kept current by `tickTimes`. */
export function timeAgo(iso, fallback = '—') {
  if (!iso) return fallback;
  return h('time', { datetime: iso, title: absoluteTime(iso), 'data-relative': iso }, relativeText(iso));
}

export function tickTimes(root = document) {
  for (const element of root.querySelectorAll('time[data-relative]')) {
    const text = relativeText(element.dataset.relative);
    if (element.textContent !== text) element.textContent = text;
  }
}

export function duration(seconds) {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return '—';
  const total = Math.max(0, Math.round(seconds));
  const parts = total < 60 ? [[total, 's']]
    : total < 3600 ? [[Math.floor(total / 60), 'm'], [total % 60, 's']]
      : [[Math.floor(total / 3600), 'h'], [Math.floor((total % 3600) / 60), 'm']];
  return parts.filter(([value], index) => index === 0 || value > 0).map(([value, unit]) => value + unit).join(' ');
}

export const secondsBetween = (from, to) =>
  (from && to ? (Date.parse(to) - Date.parse(from)) / 1000 : null);

// ----- small widgets ---------------------------------------------------------------

export function shortId(id) {
  const [kind, rest] = String(id).split('_');
  return rest && rest.length > 14 ? `${kind}_${rest.slice(0, 8)}…${rest.slice(-4)}` : String(id);
}

export function copyButton(value) {
  const button = h('button.button.quiet.small.icon-button', { type: 'button', title: 'Copy', 'aria-label': 'Copy' }, icon('copy'));
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      button.replaceChildren(icon('check'));
      setTimeout(() => button.replaceChildren(icon('copy')), 1200);
    } catch {
      // Clipboard access can be refused; the text stays selectable.
    }
  });
  return button;
}

/** An identifier with a copy button; `display` may shorten what is shown. */
export function copyable(value, display = value) {
  return h('span.copy', null, h('span.id', { title: value }, display), copyButton(value));
}

/** A shell command the operator runs locally, with a copy button. */
export function commandLine(text) {
  return h('div.command', null, h('code', null, text), copyButton(text));
}
