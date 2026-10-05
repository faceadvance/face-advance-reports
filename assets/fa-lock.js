/* Face Advance Reports — ล็อกหน้าเว็บด้วยรหัส 8 หลัก + สแกนนิ้ว (passkey PRF)
 *
 * ไม่มีเซิร์ฟเวอร์: ข้อมูลทุกไฟล์ใน data/*.enc เข้ารหัส AES-256-GCM · กุญแจ = PBKDF2-SHA256(รหัส, salt ใน data/meta.json)
 * - ไม่มีรหัสผ่านหรือข้อมูลดิบในโค้ดหน้าเว็บ · ใส่รหัสผิด = ถอด manifest ไม่ผ่าน (GCM ตรวจความถูกต้องเอง)
 * - ปลดล็อกแล้วเก็บกุญแจไว้ใน sessionStorage (ปิดแท็บ = ล็อกใหม่)
 * - สแกนนิ้ว: passkey บนเครื่อง + ส่วนขยาย PRF ให้ค่าลับ 32 ไบต์ → ใช้ห่อกุญแจเก็บใน localStorage
 *   (ไม่มีนิ้ว/Face ID = แกะกุญแจไม่ได้) · เครื่อง/เบราว์เซอร์ที่ไม่รองรับ PRF ใช้รหัสแทน
 *
 * ใช้: FALock.open() → Promise<CryptoKey> · FALock.manifest() → รายการรายงาน · FALock.load(name) → Promise<object> · FALock.lock()
 */
(() => {
  const BASE = new URL('..', document.currentScript.src);   // assets/ → รากเว็บ
  const SK = 'fa.k', PK = 'fa.pk', FK = 'fa.fail';
  const LEN = 8;
  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = (u8) => btoa(String.fromCharCode(...new Uint8Array(u8)));
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const sub = crypto.subtle;
  let META = null, KEY = null, MANIFEST = null;

  async function getJSON(p) {
    const r = await fetch(new URL(p, BASE), { cache: 'no-cache' });
    if (!r.ok) throw new Error(`โหลด ${p} ไม่ได้ (${r.status})`);
    return r.json();
  }
  const meta = async () => META || (META = await getJSON('data/meta.json'));

  async function derive(pin) {
    const m = await meta();
    const base = await sub.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveKey']);
    return sub.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(m.salt), iterations: m.iter }, base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  async function decrypt(key, f) {
    const pt = await sub.decrypt({ name: 'AES-GCM', iv: unb64(f.iv) }, key, unb64(f.ct));
    return JSON.parse(td.decode(pt));
  }
  // กุญแจถูก = ถอด manifest ได้
  async function verify(key) { MANIFEST = await decrypt(key, await getJSON('data/manifest.enc')); return key; }
  const importRaw = (raw) => sub.importKey('raw', raw, { name: 'AES-GCM' }, true, ['decrypt']);

  async function fromSession() {
    const s = sessionStorage.getItem(SK);
    if (!s) return null;
    try { return await verify(await importRaw(unb64(s))); } catch { sessionStorage.removeItem(SK); return null; }
  }
  async function keep(key) { sessionStorage.setItem(SK, b64(await sub.exportKey('raw', key))); KEY = key; }

  /* ---------- passkey + PRF ---------- */
  const PRF_SALT = te.encode('face-advance-reports/prf/v1');
  const hasPK = () => !!localStorage.getItem(PK);
  async function prfCapable() {
    if (!window.PublicKeyCredential || !isSecureContext) return false;
    try {
      if (PublicKeyCredential.getClientCapabilities) {
        const c = await PublicKeyCredential.getClientCapabilities();
        if (c && 'extension:prf' in c) return !!c['extension:prf'];
      }
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch { return false; }
  }
  async function prfGet(idB64) {
    const a = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)), userVerification: 'required', timeout: 60000,
      allowCredentials: idB64 ? [{ type: 'public-key', id: unb64(idB64) }] : [],
      extensions: { prf: { eval: { first: PRF_SALT } } } } });
    const r = a && a.getClientExtensionResults().prf;
    if (!r || !r.results || !r.results.first) throw new Error('noprf');
    return { id: b64(a.rawId), secret: new Uint8Array(r.results.first) };
  }
  const wrapKey = (secret) => sub.importKey('raw', secret, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  async function enroll(key) {
    const c = await navigator.credentials.create({ publicKey: {
      rp: { name: 'Face Advance Reports' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'face-advance-reports', displayName: 'Face Advance รายงาน' },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' },
      timeout: 60000, extensions: { prf: { eval: { first: PRF_SALT } } } } });
    const ext = c.getClientExtensionResults().prf || {};
    const id = b64(c.rawId);
    let secret = ext.results && ext.results.first ? new Uint8Array(ext.results.first) : null;
    if (!secret) {
      if (ext.enabled === false) throw new Error('noprf');
      secret = (await prfGet(id)).secret;   // บางเบราว์เซอร์ให้ค่า PRF ตอน get เท่านั้น (สแกนอีกครั้ง)
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await sub.encrypt({ name: 'AES-GCM', iv }, await wrapKey(secret), await sub.exportKey('raw', key));
    localStorage.setItem(PK, JSON.stringify({ id, iv: b64(iv), ct: b64(ct) }));
  }
  async function unlockByFinger() {
    const s = JSON.parse(localStorage.getItem(PK));
    const { secret } = await prfGet(s.id);
    const raw = await sub.decrypt({ name: 'AES-GCM', iv: unb64(s.iv) }, await wrapKey(secret), unb64(s.ct));
    return verify(await importRaw(raw));
  }

  /* ---------- UI ---------- */
  // ไอคอนมาตรฐาน (ไฟล์จริงจากชุดไอคอน ไม่ได้วาดเอง) · สีทองทึบเดียวกับปุ่มลบ
  // ลายนิ้วมือ = Material Icons "fingerprint" (round) · Google · Apache-2.0
  const FINGER = '<svg viewBox="0 0 24 24" fill="#e2bd72"><path d="M17.81 4.47c-.08 0-.16-.02-.23-.06C15.66 3.42 14 3 12.01 3c-1.98 0-3.86.47-5.57 1.41-.24.13-.54.04-.68-.2a.506.506 0 0 1 .2-.68C7.82 2.52 9.86 2 12.01 2c2.13 0 3.99.47 6.03 1.52.25.13.34.43.21.67a.49.49 0 0 1-.44.28zM3.5 9.72a.499.499 0 0 1-.41-.79c.99-1.4 2.25-2.5 3.75-3.27C9.98 4.04 14 4.03 17.15 5.65c1.5.77 2.76 1.86 3.75 3.25a.5.5 0 0 1-.12.7c-.23.16-.54.11-.7-.12a9.388 9.388 0 0 0-3.39-2.94c-2.87-1.47-6.54-1.47-9.4.01-1.36.7-2.5 1.7-3.4 2.96-.08.14-.23.21-.39.21zm6.25 12.07a.47.47 0 0 1-.35-.15c-.87-.87-1.34-1.43-2.01-2.64-.69-1.23-1.05-2.73-1.05-4.34 0-2.97 2.54-5.39 5.66-5.39s5.66 2.42 5.66 5.39c0 .28-.22.5-.5.5s-.5-.22-.5-.5c0-2.42-2.09-4.39-4.66-4.39s-4.66 1.97-4.66 4.39c0 1.44.32 2.77.93 3.85.64 1.15 1.08 1.64 1.85 2.42.19.2.19.51 0 .71-.11.1-.24.15-.37.15zm7.17-1.85c-1.19 0-2.24-.3-3.1-.89-1.49-1.01-2.38-2.65-2.38-4.39 0-.28.22-.5.5-.5s.5.22.5.5c0 1.41.72 2.74 1.94 3.56.71.48 1.54.71 2.54.71.24 0 .64-.03 1.04-.1.27-.05.53.13.58.41.05.27-.13.53-.41.58-.57.11-1.07.12-1.21.12zM14.91 22c-.04 0-.09-.01-.13-.02-1.59-.44-2.63-1.03-3.72-2.1a7.297 7.297 0 0 1-2.17-5.22c0-1.62 1.38-2.94 3.08-2.94s3.08 1.32 3.08 2.94c0 1.07.93 1.94 2.08 1.94s2.08-.87 2.08-1.94c0-3.77-3.25-6.83-7.25-6.83-2.84 0-5.44 1.58-6.61 4.03-.39.81-.59 1.76-.59 2.8 0 .78.07 2.01.67 3.61.1.26-.03.55-.29.64-.26.1-.55-.04-.64-.29a11.14 11.14 0 0 1-.73-3.96c0-1.2.23-2.29.68-3.24 1.33-2.79 4.28-4.6 7.51-4.6 4.55 0 8.25 3.51 8.25 7.83 0 1.62-1.38 2.94-3.08 2.94s-3.08-1.32-3.08-2.94c0-1.07-.93-1.94-2.08-1.94s-2.08.87-2.08 1.94c0 1.71.66 3.31 1.87 4.51.95.94 1.86 1.46 3.27 1.85.27.07.42.35.35.61-.05.23-.26.38-.47.38z"/></svg>';
  // สแกนหน้า = Tabler Icons "face-id" · MIT
  const FACE = '<svg viewBox="0 0 24 24" fill="none" stroke="#e2bd72" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 8v-2a2 2 0 0 1 2 -2h2"/><path d="M4 16v2a2 2 0 0 0 2 2h2"/><path d="M16 4h2a2 2 0 0 1 2 2v2"/><path d="M16 20h2a2 2 0 0 0 2 -2v-2"/><path d="M9 10l.01 0"/><path d="M15 10l.01 0"/><path d="M9.5 15a3.5 3.5 0 0 0 5 0"/></svg>';
  // เว็บแยก Face ID / Touch ID ตรงๆ ไม่ได้ → เดาจากเครื่อง: iPhone จอสูง ≥ 812pt (X ขึ้นไป) = สแกนหน้า · นอกนั้น = ลายนิ้วมือ
  const IS_FACE = /iPhone/.test(navigator.userAgent) && Math.max(screen.width, screen.height) >= 812;
  const BIO = IS_FACE ? { icon: FACE, name: 'สแกนหน้า', btn: 'ปุ่มสแกนหน้า', short: 'Face ID' } : { icon: FINGER, name: 'สแกนลายนิ้วมือ', btn: 'ปุ่มลายนิ้วมือ', short: 'สแกนนิ้ว' };
  const BACK = '<svg viewBox="0 0 24 24"><path d="M8.6 5h11A1.4 1.4 0 0 1 21 6.4v11.2a1.4 1.4 0 0 1-1.4 1.4h-11a1.4 1.4 0 0 1-1-.4L2.4 12.7a1 1 0 0 1 0-1.4l5.2-5.9a1.4 1.4 0 0 1 1-.4z" fill="#e2bd72"/><path d="M11.2 9.2l5.6 5.6m0-5.6l-5.6 5.6" stroke="#17140e" stroke-width="2" stroke-linecap="round"/></svg>';
  let ui = null;

  function build() {
    const el = document.createElement('div');
    el.className = 'fal';
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-label', 'ใส่รหัสผ่านเพื่อเข้าดูรายงาน');
    el.innerHTML = `<div class="fal-card">
      <div class="fal-logo"><img src="${new URL('assets/fmark.png', BASE)}" alt=""></div>
      <div class="fal-word">FACE <b>ADVANCE</b></div>
      <p class="fal-sub">ใส่รหัสผ่านเพื่อเข้าดูรายงาน</p>
      <div class="fal-dots" aria-live="polite">${'<i></i>'.repeat(LEN)}</div>
      <div class="fal-pad">
        ${[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => `<button class="fal-key" data-k="${n}" aria-label="${n}">${n}</button>`).join('')}
        <button class="fal-key ghost" data-k="finger" aria-label="${BIO.name}">${BIO.icon}</button>
        <button class="fal-key" data-k="0" aria-label="0">0</button>
        <button class="fal-key ghost" data-k="back" aria-label="ลบ">${BACK}</button>
      </div>
      <div class="fal-offer"><p>เปิดใช้${BIO.name}บนเครื่องนี้ไหมคะ<br>ครั้งหน้าเปิดแล้วสแกนอัตโนมัติ ไม่ต้องใส่รหัส</p>
        <button class="fal-btn gold" data-k="enroll">เปิดใช้${BIO.short}</button><button class="fal-btn plain" data-k="skip">ไม่ตอนนี้</button></div>
      <div class="fal-busy"></div>
      <div class="fal-msg"></div>
    </div>`;
    document.body.appendChild(el);
    return el;
  }

  function open() {
    if (KEY) return Promise.resolve(KEY);
    return fromSession().then((k) => k ? (KEY = k) : ask());
  }

  function ask() {
    return new Promise((resolve) => {
      ui = ui || build();
      ui.hidden = false;
      document.documentElement.style.overflow = 'hidden';
      const dots = ui.querySelector('.fal-dots'), msg = ui.querySelector('.fal-msg');
      let pin = '', busy = false, prf = null;
      prfCapable().then((v) => { prf = v; if (!busy) hint(); });
      const say = (t, ok) => { msg.textContent = t; msg.classList.toggle('ok', !!ok); };
      const hint = () => say(hasPK() ? `แตะ${BIO.btn}เพื่อสแกน หรือใส่รหัสผ่าน` : 'ใส่รหัสผ่าน 8 หลัก', true);
      const paint = () => dots.querySelectorAll('i').forEach((d, i) => d.classList.toggle('on', i < pin.length));
      const lockedFor = () => { const f = JSON.parse(localStorage.getItem(FK) || '{"n":0,"t":0}'); return Math.max(0, f.t - Date.now()); };
      const done = (key) => {
        dots.className = 'fal-dots ok';
        setTimeout(() => { ui.hidden = true; ui.classList.remove('offer'); document.documentElement.style.overflow = ''; dots.className = 'fal-dots'; pin = ''; paint(); resolve(key); }, 220);
      };
      async function success(key, viaFinger) {
        localStorage.removeItem(FK);
        await keep(key);
        if (!viaFinger && !hasPK() && prf && !localStorage.getItem('fa.noask')) {
          ui.classList.remove('busy'); ui.classList.add('offer'); say('');
          ui.dataset.pending = '1';
          ui._key = key; ui._done = done;
          return;
        }
        done(key);
      }
      async function submit() {
        const wait = lockedFor();
        if (wait) { fail(`ใส่ผิดหลายครั้ง รออีก ${Math.ceil(wait / 1000)} วินาที`); return; }
        busy = true; ui.classList.add('busy'); say('กำลังตรวจรหัส…', true);
        try {
          const key = await verify(await derive(pin));
          ui.classList.remove('busy'); busy = false;
          await success(key, false);
        } catch (e) {
          ui.classList.remove('busy'); busy = false;
          if (e && e.name === 'OperationError') {
            const f = JSON.parse(localStorage.getItem(FK) || '{"n":0,"t":0}');
            f.n += 1;
            if (f.n >= 5) f.t = Date.now() + Math.min(300, 30 * 2 ** (f.n - 5)) * 1000;   // ผิด 5 ครั้ง → รอ 30 วิ แล้วเพิ่มเท่าตัว (สูงสุด 5 นาที)
            localStorage.setItem(FK, JSON.stringify(f));
            fail(f.n >= 5 ? `รหัสไม่ถูกต้อง · รอ ${Math.ceil((f.t - Date.now()) / 1000)} วินาทีแล้วลองใหม่` : 'รหัสไม่ถูกต้อง ลองใหม่อีกครั้ง');
          } else fail('โหลดข้อมูลไม่ได้ ตรวจอินเทอร์เน็ตแล้วลองใหม่');
        }
      }
      function fail(t) {
        say(t); dots.className = 'fal-dots err fal-shake'; if (navigator.vibrate) navigator.vibrate(120);
        setTimeout(() => { dots.className = 'fal-dots'; pin = ''; paint(); }, 450);
      }
      async function finger(auto) {
        if (!hasPK()) { say(prf === false ? `เครื่อง/เบราว์เซอร์นี้ยัง${BIO.name}ไม่ได้ ใส่รหัสผ่านแทนนะคะ` : `ใส่รหัสผ่านครั้งแรกก่อน แล้วเปิดใช้${BIO.name}ได้`); return; }
        busy = true; ui.classList.add('busy'); say('กำลังสแกน…', true);
        try { const key = await unlockByFinger(); ui.classList.remove('busy'); busy = false; await success(key, true); }
        catch (e) {
          ui.classList.remove('busy'); busy = false;
          // สแกนอัตโนมัติถูกเบราว์เซอร์ปัด (ต้องแตะก่อน) / ผู้ใช้กดยกเลิก → แค่บอกให้แตะปุ่ม ไม่ลบที่ลงไว้
          if (auto || (e && e.name === 'NotAllowedError')) hint();
          else { localStorage.removeItem(PK); say(`${BIO.name}ใช้ไม่ได้แล้ว ใส่รหัสผ่านแล้วเปิดใช้ใหม่นะคะ`); }
        }
      }
      function press(k) {
        if (busy) return;
        if (k === 'enroll') {
          busy = true; ui.classList.add('busy');
          enroll(ui._key).then(() => { busy = false; ui.classList.remove('busy'); ui._done(ui._key); })
            .catch((e) => { busy = false; ui.classList.remove('busy'); if (e && e.message === 'noprf') localStorage.setItem('fa.noask', '1'); say(e && e.message === 'noprf' ? 'เครื่องนี้ยังไม่รองรับ ใช้รหัสผ่านต่อได้เลยค่ะ' : 'ยังไม่ได้เปิดใช้ · ลองใหม่ครั้งหน้าได้'); setTimeout(() => ui._done(ui._key), 1200); });
          return;
        }
        if (k === 'skip') { localStorage.setItem('fa.noask', '1'); ui._done(ui._key); return; }
        if (k === 'finger') { finger(); return; }
        if (k === 'back') { pin = pin.slice(0, -1); paint(); return; }
        if (pin.length >= LEN) return;
        pin += k; paint();
        if (pin.length === LEN) setTimeout(submit, 120);
      }
      ui.onclick = (e) => { const b = e.target.closest('[data-k]'); if (b) press(b.dataset.k); };
      ui.onkeydown = null;
      document.onkeydown = (e) => {
        if (ui.hidden || ui.classList.contains('offer')) return;
        if (/^\d$/.test(e.key)) { press(e.key); flash(e.key); }
        else if (e.key === 'Backspace') { press('back'); flash('back'); }
      };
      const flash = (k) => { const b = ui.querySelector(`[data-k="${k}"]`); if (b) { b.classList.add('press'); setTimeout(() => b.classList.remove('press'), 110); } };
      paint();
      if (hasPK()) setTimeout(() => { if (!busy && !ui.hidden && !pin) finger(true); }, 250);   // ลงไว้แล้ว → สแกนให้เลยตอนเปิด
    });
  }

  async function load(name) {
    const key = await open();
    return decrypt(key, await getJSON(`data/${name}.enc`));
  }
  function lock() { sessionStorage.removeItem(SK); KEY = null; location.reload(); }
  function forgetFinger() { localStorage.removeItem(PK); localStorage.removeItem('fa.noask'); }

  const manifest = () => open().then(() => MANIFEST);
  window.FALock = { open, manifest, load, lock, forgetFinger, base: BASE.href };
})();
