#!/usr/bin/env node
// เข้ารหัสข้อมูลรายงาน (JSON ดิบ) → data/<name>.enc ที่ขึ้น GitHub ได้
//
// - AES-256-GCM · กุญแจจาก PBKDF2-SHA256 ของรหัสผ่าน (salt + รอบ อยู่ใน data/meta.json · ใช้ร่วมทุกไฟล์ ปลดครั้งเดียวเปิดได้ทุกรายงาน)
// - รหัสผ่านอ่านจาก env REPORTS_PASS เท่านั้น (เก็บใน ~/.claude/secrets.env) · ไม่พิมพ์ออกมา · ไม่เขียนลงไฟล์ใน repo
// - ไฟล์ JSON ดิบเก็บนอก repo (../reports-src/) ห้ามวางใน repo
//
// ใช้:  node tools/encrypt.mjs <src.json> <name>        → data/<name>.enc
//       node tools/encrypt.mjs --check <name>           → ลองถอดด้วยรหัสใน env (ตรวจหลังเข้ารหัส)
import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA = path.join(ROOT, 'data');
const META = path.join(DATA, 'meta.json');
const ITER = 600000;   // OWASP 2023 สำหรับ PBKDF2-SHA256 · มือถือใช้ ~0.5–1.5 วิ ครั้งเดียวต่อการปลดล็อก
const b64 = (u8) => Buffer.from(u8).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const die = (m) => { console.error('✗ ' + m); process.exit(1); };

function meta() {
  if (!fs.existsSync(META)) {
    const m = { v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, salt: b64(crypto.getRandomValues(new Uint8Array(16))) };
    fs.mkdirSync(DATA, { recursive: true });
    fs.writeFileSync(META, JSON.stringify(m, null, 2) + '\n');
    console.log('สร้าง data/meta.json (salt ใหม่) · ไฟล์ .enc เดิมทั้งหมดต้องเข้ารหัสใหม่');
  }
  return JSON.parse(fs.readFileSync(META, 'utf8'));
}

async function key(pass, m) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(m.salt), iterations: m.iter },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

const pass = process.env.REPORTS_PASS;
if (!pass) die('ไม่มี REPORTS_PASS ใน env (source ~/.claude/secrets.env ก่อน)');
if (!/^\d{8}$/.test(pass)) die('REPORTS_PASS ต้องเป็นตัวเลข 8 หลัก (หน้าเว็บรับแค่ 8 หลัก)');
const args = process.argv.slice(2);
const m = meta();
const k = await key(pass, m);

if (args[0] === '--check') {
  const name = args[1] || die('ระบุชื่อไฟล์');
  const f = JSON.parse(fs.readFileSync(path.join(DATA, name + '.enc'), 'utf8'));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(f.iv) }, k, unb64(f.ct)).catch(() => die('ถอดรหัสไม่ได้ (รหัส/salt ไม่ตรง)'));
  const j = JSON.parse(new TextDecoder().decode(pt));
  console.log(`✓ ${name}.enc ถอดได้ · ${Object.keys(j).length} คีย์บนสุด`);
} else {
  const [src, name] = args;
  if (!src || !name || !/^[a-z0-9-]+$/.test(name)) die('ใช้: node tools/encrypt.mjs <src.json> <name a-z0-9->');
  if (path.resolve(src).startsWith(ROOT + path.sep)) die('ไฟล์ดิบต้องอยู่นอก repo');
  const raw = fs.readFileSync(src, 'utf8');
  JSON.parse(raw);   // ต้องเป็น JSON ถูกต้อง
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(raw)));
  const out = path.join(DATA, name + '.enc');
  fs.writeFileSync(out + '.tmp', JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) }));
  fs.renameSync(out + '.tmp', out);
  console.log(`✓ data/${name}.enc · ${raw.length.toLocaleString()} → ${ct.length.toLocaleString()} ไบต์`);
}
