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
  // ลายนิ้วมือ (โครงจาก Lucide "fingerprint" · ISC) ไล่สีทองแบบโลโก้
  const FINGER = '<svg viewBox="0 0 24 24" fill="none" stroke="url(#falg)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><defs><linearGradient id="falg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#f3e3a8"/><stop offset="1" stop-color="#b08a52"/></linearGradient></defs><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>';
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
        <button class="fal-key ghost" data-k="finger" aria-label="สแกนลายนิ้วมือ">${FINGER}</button>
        <button class="fal-key" data-k="0" aria-label="0">0</button>
        <button class="fal-key ghost" data-k="back" aria-label="ลบ">${BACK}</button>
      </div>
      <div class="fal-offer"><p>เปิดใช้สแกนลายนิ้วมือ / Face ID บนเครื่องนี้ไหมคะ<br>ครั้งหน้าไม่ต้องใส่รหัส</p>
        <button class="fal-btn gold" data-k="enroll">เปิดใช้สแกนนิ้ว</button><button class="fal-btn plain" data-k="skip">ไม่ตอนนี้</button></div>
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
      prfCapable().then((v) => { prf = v; hint(); });
      const say = (t, ok) => { msg.textContent = t; msg.classList.toggle('ok', !!ok); };
      const hint = () => say(hasPK() ? 'แตะปุ่มลายนิ้วมือเพื่อสแกน หรือใส่รหัสผ่าน' : 'ใส่รหัสผ่าน 8 หลัก', true);
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
      async function finger() {
        if (!hasPK()) { say(prf === false ? 'เครื่อง/เบราว์เซอร์นี้ยังสแกนนิ้วไม่ได้ ใส่รหัสผ่านแทนนะคะ' : 'ใส่รหัสผ่านครั้งแรกก่อน แล้วเปิดใช้สแกนนิ้วได้'); return; }
        busy = true; ui.classList.add('busy'); say('กำลังสแกน…', true);
        try { const key = await unlockByFinger(); ui.classList.remove('busy'); busy = false; await success(key, true); }
        catch (e) {
          ui.classList.remove('busy'); busy = false;
          if (e && e.name === 'NotAllowedError') hint();
          else { localStorage.removeItem(PK); say('สแกนนิ้วใช้ไม่ได้แล้ว ใส่รหัสผ่านแล้วเปิดใช้ใหม่นะคะ'); }
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
