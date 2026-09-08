const app = document.getElementById('app');
const MAX_PHOTO_BYTES = 5 * 1024 * 1024;
let signed_in = false;
let github_attempt = 0;

// A service sending its browser here to sign in lands on /authorize with a
// redirect_uri. The destination is stashed so it survives the Discord round
// trip, and honored the moment a token exists.
{
  const query = new URLSearchParams(location.search);
  if (query.get('redirect_uri')) {
    sessionStorage.setItem('identity_authorize', JSON.stringify({
      redirect_uri: query.get('redirect_uri'),
      state: query.get('state') || '',
      code_challenge: query.get('code_challenge') || '',
    }));
  }
}

async function maybeHandoff() {
  const raw = sessionStorage.getItem('identity_authorize');
  if (!raw || !signed_in) return false;
  const {redirect_uri, state, code_challenge} = JSON.parse(raw);

  const response = await api('POST', '/v1/handoff', {redirect_uri, code_challenge});
  if (response.status === 401) { signed_in = false; return false; }
  sessionStorage.removeItem('identity_authorize');
  if (!response.ok) { await fail(response); return true; }
  const {code} = await response.json();

  show(el('p', {class: 'muted'}, 'Signing you in…'));
  const glue = redirect_uri.includes('?') ? '&' : '?';
  location.replace(redirect_uri + glue +
    'code=' + encodeURIComponent(code) + '&state=' + encodeURIComponent(state));
  return true;
}

const api = (method, path, body) => fetch(path, {
  method,
  headers: Object.assign(
    {'Content-Type': 'application/json', 'X-Identity-Browser': '1'}),
  body: body === undefined ? undefined : JSON.stringify(body),
});

const el = (tag, attrs, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'onclick') node.addEventListener('click', v);
    else if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    node.append(child);
  }
  return node;
};

// Provider brand marks, inlined so the page stays self-contained.
// Path data from Simple Icons (CC0), viewBox 0 0 24 24.
const ICON_PATHS = {
  github: 'M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385' +
    '.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61' +
    '-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084' +
    '-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495' +
    '.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0' +
    '-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322' +
    ' 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552' +
    ' 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91' +
    ' 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0' +
    ' 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24' +
    ' 17.592 24 12.297c0-6.627-5.373-12-12-12',
  discord: 'M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0' +
    ' 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68' +
    '-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00' +
    '-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321' +
    '.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312' +
    '.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842' +
    '-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057' +
    'c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c' +
    '.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278' +
    ' 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246' +
    '.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873' +
    '.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a' +
    '.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077' +
    '.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061' +
    ' 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419' +
    ' 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568' +
    ' 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569' +
    '-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0' +
    ' 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z',
};

const SVG_NS = 'http://www.w3.org/2000/svg';
function icon(provider) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', ICON_PATHS[provider] || '');
  path.setAttribute('fill', 'currentColor');
  svg.append(path);
  return svg;
}

const show = (...nodes) => { app.replaceChildren(...nodes); };

// -- signed out ------------------------------------------------------------

async function signedOut(message) {
  const nodes = [];
  if (message) nodes.push(el('p', {class: 'error'}, message));
  nodes.push(el('div', {class: 'signin'},
    el('button', {class: 'provider', onclick: () => startGitHub()},
      icon('github'), 'Sign in with GitHub'),
    el('button', {class: 'provider', onclick: startDiscord},
      icon('discord'), 'Sign in with Discord')));
  show(...nodes);
  const providers = await fetch('/providers').then(r => r.json());
  for (const button of app.querySelectorAll('.provider')) {
    if (button.textContent.includes('GitHub') && !providers.github) button.remove();
    if (button.textContent.includes('Discord') && !providers.discord) button.remove();
  }
}

async function startGitHub(linking) {
  const attempt = ++github_attempt;
  const start = await api('POST', '/signin/github/start');
  if (!start.ok) return fail(start);
  const device = await start.json();

  show(
    el('p', {}, 'Go to ', el('a', {href: device.verification_uri, target: '_blank'},
      device.verification_uri), ' and enter this code:'),
    el('div', {class: 'device-code'}, device.user_code),
    el('p', {class: 'muted'}, 'Waiting for GitHub…'),
    el('div', {class: 'row'},
      el('button', {onclick: () => render()}, 'Cancel')));

  let interval = (device.interval || 5) + 1;
  const deadline = Date.now() + (device.expires_in || 900) * 1000;
  while (attempt === github_attempt && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, interval * 1000));
    if (attempt !== github_attempt) return;
    const finish = await api('POST', '/signin/github/finish',
      {device_code: device.device_code});
    if (attempt !== github_attempt) return;
    if (finish.status === 202) {
      if ((await finish.json()).status === 'slow_down') interval += 5;
      continue;
    }
    if (finish.status === 201) {
      signed_in = true;
      return render();
    }
    if (finish.ok) return render();  // a completed link answers 200
    return fail(finish);
  }
}

async function startDiscord() {
  const start = await api('POST', '/signin/discord/start');
  if (!start.ok) return fail(start);
  const body = await start.json();
  location.href = body.url;
}

async function fail(response) {
  let message = 'something went wrong';
  try { message = (await response.json()).error || message; } catch {}
  show(el('p', {class: 'error'}, message), el('button', {onclick: boot}, 'Try again'));
}

// -- signed in -------------------------------------------------------------

async function signedIn(message) {
  const who = await api('GET', '/v1/whoami');
  if (who.status === 401) {
    signed_in = false;
    return signedOut('that session no longer works; sign in again');
  }
  if (!who.ok) return fail(who);
  const me = await who.json();

  const tokens = await api('GET', '/v1/tokens');
  const tokenRows = tokens.ok ? (await tokens.json()).tokens : [];

  const nodes = [];
  if (message) nodes.push(el('p', {class: 'error'}, message));

  nodes.push(el('p', {},
    'Signed in as ', el('strong', {}, me.handle), ' ',
    el('span', {class: 'muted mono'}, '(' + me.account + ')')));

  if (me.avatar_upload_enabled) {
    const photo_input = el('input', {type: 'file', accept: 'image/jpeg,image/png,image/webp', 'aria-label': 'Choose profile photo'});
    photo_input.addEventListener('change', async () => {
      const file = photo_input.files[0];
      if (!file) return;
      if (file.size > MAX_PHOTO_BYTES) return signedIn('Choose an image no larger than 5 MiB.');
      photo_input.disabled = true;
      try {
        const response = await fetch('/v1/avatar', {method: 'POST', headers: {'Content-Type': file.type, 'X-Identity-Browser': '1'}, body: file});
        if (!response.ok) return signedIn((await response.json()).error);
        await signedIn();
      } catch { await signedIn('Could not upload the photo. Try again.'); }
    });
    nodes.push(el('h2', {}, 'profile photo'));
    if (me.avatar) {
      const picture_url = size => '/v1/avatar?size=' + size + '&v=' + encodeURIComponent(me.avatar.id);
      nodes.push(el('img', {src: picture_url(96), srcset: picture_url(192) + ' 2x, ' + picture_url(288) + ' 3x', width: '96', height: '96', alt: 'Your profile photo', class: 'avatar'}));
    }
    nodes.push(photo_input, el('p', {class: 'muted'}, 'JPEG, PNG or WebP. Up to 5 MiB, 16 megapixels and 8192 pixels per side.'));
    if (me.avatar) nodes.push(el('button', {onclick: async () => {
      const response = await api('DELETE', '/v1/avatar');
      if (!response.ok) return fail(response);
      await signedIn();
    }}, 'Remove photo'));
  }

  // Identities, and the link buttons for whichever provider is missing.
  const linked = new Set(me.identities.map(i => i.provider));
  const identitySection = [el('h2', {}, 'identities')];
  for (const identity of me.identities) {
    identitySection.push(el('p', {class: 'identity'},
      icon(identity.provider), el('strong', {}, identity.handle),
      el('span', {class: 'muted'}, identity.provider)));
  }
  const linkButtons = [];
  if (!linked.has('github'))
    linkButtons.push(el('button', {class: 'provider', onclick: () => startGitHub(true)},
      icon('github'), 'Link GitHub'));
  if (!linked.has('discord'))
    linkButtons.push(el('button', {class: 'provider', onclick: startDiscord},
      icon('discord'), 'Link Discord'));
  if (linkButtons.length)
    identitySection.push(el('div', {class: 'row'}, ...linkButtons));
  nodes.push(...identitySection);

  // Tokens.
  nodes.push(el('h2', {}, 'tokens'));
  const table = el('table', {},
    el('tr', {}, el('th', {}, 'name'), el('th', {}, 'expires'), el('th', {}, '')));
  for (const row of tokenRows) {
    const expires = row.revoked ? 'revoked'
      : row.expires_at ? new Date(row.expires_at).toLocaleDateString() : 'never';
    table.append(el('tr', {},
      el('td', {}, row.name + (row.current ? ' (this session)' : '')),
      el('td', {class: 'muted'}, expires),
      el('td', {}, row.revoked ? '' :
        el('button', {class: 'danger', onclick: () => revoke(row.id)}, 'revoke'))));
  }
  nodes.push(el('div', {class: 'table-wrap'}, table));

  const nameInput = el('input', {type: 'text', placeholder: 'token name'});
  nodes.push(el('div', {class: 'row'},
    nameInput,
    el('button', {onclick: () => mint(nameInput.value)}, 'New token'),
    el('button', {onclick: signOut}, 'Sign out')));

  show(...nodes);
}

async function mint(name) {
  const response = await api('POST', '/v1/tokens', {name});
  if (!response.ok) return fail(response);
  const minted = await response.json();
  await signedIn();
  app.prepend(
    el('p', {}, 'Copy it now; it is not shown again: ',
      el('code', {}, minted.token)));
}

async function revoke(id) {
  const response = await api('DELETE', '/v1/tokens/' + id);
  if (!response.ok && response.status !== 404) return fail(response);
  render();
}

async function signOut() {
  await api('POST', '/session/logout', {});
  signed_in = false;
  render();
}

async function render(message) {
  github_attempt++;
  if (signed_in && await maybeHandoff()) return;
  if (signed_in) signedIn(message); else signedOut(message);
}

async function boot() {
  const response = await api('GET', '/v1/whoami');
  if (!response.ok && response.status !== 401) {
    show(el('p', {class: 'error'}, 'Sign-in is temporarily unavailable. Reload to retry.'));
    return;
  }
  signed_in = response.ok;
  render();
}
boot();
