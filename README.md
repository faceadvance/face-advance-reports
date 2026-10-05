# Face Advance · รายงาน

เว็บหลักสำหรับรวมรายงานวิเคราะห์ของ Face Advance — https://faceadvance.github.io/face-advance-reports/

## ความปลอดภัย
- **ไม่มีรหัสผ่าน และไม่มีข้อมูลดิบในโค้ด** · ทุกอย่าง (รายชื่อรายงาน + หน้ารายงานทั้งหน้า) อยู่ใน `data/*.enc` ที่เข้ารหัส AES-256-GCM
- กุญแจ = PBKDF2-SHA256(รหัส 8 หลัก, salt ใน `data/meta.json`, 600,000 รอบ) · ใส่รหัสผิด = ถอดไม่ออก
- ปลดล็อกแล้วเก็บกุญแจใน sessionStorage (ปิดแท็บ = ล็อก) · ผิด 5 ครั้งรอ 30 วิ → เพิ่มเท่าตัว (สูงสุด 5 นาที, ฝั่งเครื่องผู้ใช้)
- สแกนนิ้ว/Face ID = passkey + ส่วนขยาย PRF ห่อกุญแจเก็บในเครื่อง (iOS 18+ / Chrome / Android) · เครื่องที่ไม่รองรับใช้รหัสแทน
  - ลงไว้แล้ว → เปิดหน้าแล้วสแกนอัตโนมัติ · iPhone จอ ≥ 812pt แสดงเป็น "สแกนหน้า" (เว็บแยก Face ID/Touch ID ตรงๆ ไม่ได้ จึงเดาจากรุ่น)
- ระดับ: กันคนทั่วไปเข้าดู ไม่ใช่กันผู้เชี่ยวชาญที่ตั้งใจเจาะ (รหัสตัวเลข 8 หลัก เดาออฟไลน์ได้ถ้ามีเครื่องแรง)

## เพิ่ม/อัปเดตรายงาน
ชื่อไฟล์ใน `data/` เป็นรหัสสุ่ม (ไม่บอกหัวข้อรายงาน) · ตารางจับคู่ slug ↔ ไฟล์ ↔ สคริปต์สร้าง อยู่ที่ `../reports-src/README.md` (นอก repo)
1. สร้าง JSON ดิบไว้ **นอก repo** ที่ `../reports-src/<slug>.json` รูปแบบ `{"v":1,"html":"<หน้ารายงานทั้งหน้า>"}`
   (หน้ารายงานควรมีปุ่ม `href="./"` กลับหน้ารวม และปุ่มล็อกที่ลบ `sessionStorage['fa.k']`)
2. สุ่ม id แล้วเพิ่มรายการใน `../reports-src/manifest.json` → `{"slug","file":"<id>","tag","title","desc","meta"}`
3. เข้ารหัส (รหัสอ่านจาก `REPORTS_PASS` ใน `~/.claude/secrets.env`):
   ```sh
   set -a; source ~/.claude/secrets.env; set +a
   node tools/encrypt.mjs ../reports-src/<slug>.json <id>
   node tools/encrypt.mjs ../reports-src/manifest.json manifest
   node tools/encrypt.mjs --check <id>
   ```
4. บันทึก `CHANGELOG.md` (ไม่ต้องระบุตัวเลข/ชื่อสินค้า) แล้ว commit + push (GitHub Pages deploy ให้เอง)

**เปลี่ยนรหัส:** แก้ `REPORTS_PASS` → ลบ `data/meta.json` (ได้ salt ใหม่) → เข้ารหัสทุกไฟล์ใหม่ · passkey เดิมทุกเครื่องจะใช้ไม่ได้ ต้องใส่รหัสใหม่แล้วเปิดใช้ใหม่
