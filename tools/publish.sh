#!/usr/bin/env bash
# เอารายงานขึ้นเว็บ Face Advance · รายงาน ในคำสั่งเดียว
#   เข้ารหัส → เพิ่ม/อัปเดตรายการหน้ารวม → CHANGELOG (มี hash + เวลา) → commit → push → รอจนเว็บจริงตรง
#
# ใช้:
#   tools/publish.sh <slug> <report.html> [--title "..."] [--desc "..."] [--tag "..."] [--meta "..."] [--dry-run] [--force]
#     slug        = ชื่อใน URL (?r=slug) · a-z 0-9 - · ใหม่ต้องมี --title
#     report.html = หน้ารายงานทั้งหน้า (ข้อมูลฝังในหน้าแล้ว) · ต้องมีปุ่ม href="./" และปุ่มออกจากระบบที่ลบ sessionStorage 'fa.k'
#     --dry-run   = ทำทุกอย่างยกเว้น commit/push (ดูผลด้วย git status / git diff)
#     --force     = เผยแพร่แม้เนื้อหาไม่เปลี่ยนจากรอบก่อน
#
# กติกา (ดู README):
#   - ไฟล์ดิบอยู่นอก repo ที่ ../reports-src/ · รหัสอ่านจาก REPORTS_PASS ใน ~/.claude/secrets.env (ไม่พิมพ์ออก)
#   - ชื่อไฟล์ใน data/ เป็นรหัสสุ่ม · CHANGELOG ไม่ระบุชื่อ/ตัวเลขรายงาน (ก่อนใส่รหัสต้องไม่เห็นแม้หัวข้อ)
#   - commit นี้แตะได้แค่ data/ กับ CHANGELOG.md · ไฟล์อื่นค้างอยู่ = หยุด (กันเผลอ push โค้ดที่ยังไม่เทส)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$(cd "$ROOT/.." && pwd)/reports-src"
SITE="https://faceadvance.github.io/face-advance-reports"
die() { echo "✗ $*" >&2; exit 1; }

[ $# -ge 2 ] || die "ใช้: tools/publish.sh <slug> <report.html> [--title ..] [--desc ..] [--tag ..] [--meta ..] [--dry-run] [--force]"
SLUG="$1"; HTML="$2"; shift 2
TITLE=""; DESC=""; TAG=""; META=""; DRY=0; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --title) TITLE="$2"; shift 2 ;;
    --desc) DESC="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --meta) META="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --force) FORCE=1; shift ;;
    *) die "ไม่รู้จักตัวเลือก $1" ;;
  esac
done
[[ "$SLUG" =~ ^[a-z0-9-]+$ ]] || die "slug ต้องเป็น a-z 0-9 - เท่านั้น: $SLUG"
[ -f "$HTML" ] || die "ไม่เจอไฟล์ $HTML"
HTML="$(cd "$(dirname "$HTML")" && pwd)/$(basename "$HTML")"   # เป็น path เต็มก่อน cd เข้า repo
if [ -z "${REPORTS_PASS:-}" ]; then set -a; source ~/.claude/secrets.env >/dev/null 2>&1 || true; set +a; fi
[ -n "${REPORTS_PASS:-}" ] || die "ไม่มี REPORTS_PASS (ดู ~/.claude/secrets.env)"
mkdir -p "$SRC"
cd "$ROOT"

# ---- 0) repo สะอาด + ตรงกับ GitHub ----
dirty="$(git status --porcelain)"
[ -z "$dirty" ] || die "repo มีไฟล์ค้างที่ยังไม่ commit — จัดการก่อน:
$dirty"
git pull -q --ff-only || die "git pull ไม่ผ่าน (มีคนแก้ repo จากที่อื่น?)"

# ---- 1) ตรวจหน้ารายงาน + เตรียมไฟล์ดิบ + manifest ----
export SLUG HTML TITLE DESC TAG META SRC FORCE
ID="$(python3 - <<'PY'
import hashlib, json, os, secrets, sys, datetime as dt
slug, html_p, src = os.environ['SLUG'], os.environ['HTML'], os.environ['SRC']
h = open(html_p, encoding='utf-8').read()
err = lambda m: (print('✗ ' + m, file=sys.stderr), sys.exit(1))
if os.environ['REPORTS_PASS'] in h: err('หน้ารายงานมีรหัสผ่านอยู่ข้างใน — ห้ามเผยแพร่')
if 'href="./"' not in h: err('หน้ารายงานไม่มีปุ่มกลับหน้ารวม (href="./")')
if "removeItem('fa.k')" not in h: err("หน้ารายงานไม่มีปุ่มออกจากระบบ (sessionStorage.removeItem('fa.k'))")
if '__DATA__' in h: err('ยังมี __DATA__ ค้าง (ข้อมูลไม่ได้ฝังในหน้า)')
mp = os.path.join(src, 'manifest.json')
m = json.load(open(mp, encoding='utf-8')) if os.path.exists(mp) else {'v': 1, 'reports': []}
now = dt.datetime.now(dt.timezone(dt.timedelta(hours=7))).strftime('%Y-%m-%d %H:%M')
r = next((x for x in m['reports'] if x['slug'] == slug), None)
new = r is None
if new:
    if not os.environ['TITLE']: err('รายงานใหม่ต้องมี --title')
    r = {'slug': slug, 'file': secrets.token_hex(6)}
    m['reports'].insert(0, r)                       # ใหม่สุดอยู่บน
for k, e in (('title', 'TITLE'), ('desc', 'DESC'), ('tag', 'TAG')):
    if os.environ[e]: r[k] = os.environ[e]
    r.setdefault(k, '')
r['meta'] = os.environ['META'] or f'อัปเดต {now} น.'
payload = json.dumps({'v': 1, 'html': h}, ensure_ascii=False)
# เนื้อหาไม่เปลี่ยน (ไม่นับเวลาใน meta) → ไม่ต้องเผยแพร่
digest = hashlib.sha256((payload + json.dumps({k: v for k, v in r.items() if k != 'meta'}, ensure_ascii=False, sort_keys=True)).encode()).hexdigest()
pubp = os.path.join(src, '.published.json')
pub = json.load(open(pubp)) if os.path.exists(pubp) else {}
if not new and pub.get(slug) == digest and os.environ['FORCE'] != '1':
    print('SAME'); sys.exit(0)
open(os.path.join(src, slug + '.json'), 'w', encoding='utf-8').write(payload)
json.dump(m, open(mp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
open(os.path.join(src, '.pending.json'), 'w').write(json.dumps({'slug': slug, 'digest': digest, 'new': new}))
print(r['file'])
PY
)"
[ "$ID" = "SAME" ] && { echo "= เนื้อหาเหมือนรอบก่อน ไม่ต้องเผยแพร่ (ใช้ --force ถ้าต้องการ)"; exit 0; }
[[ "$ID" =~ ^[0-9a-f]{12}$ ]] || die "สร้าง id ไม่สำเร็จ: $ID"
NEW="$(python3 -c "import json;print(json.load(open('$SRC/.pending.json'))['new'])")"

# ---- 2) เข้ารหัส + ตรวจถอดได้ ----
node tools/encrypt.mjs "$SRC/$SLUG.json" "$ID" >/dev/null
node tools/encrypt.mjs "$SRC/manifest.json" manifest >/dev/null
node tools/encrypt.mjs --check "$ID" >/dev/null && node tools/encrypt.mjs --check manifest >/dev/null || die "ถอดรหัสไฟล์ที่เพิ่งสร้างไม่ได้"
echo "✓ เข้ารหัส data/$ID.enc + manifest"

# ---- 3) CHANGELOG (ไม่ระบุชื่อ/ตัวเลขรายงาน) ----
TS="$(TZ=Asia/Bangkok date '+%Y-%m-%d %H:%M')"
if [ "$NEW" = "True" ]; then LINE="- ➕ เพิ่มรายงานใหม่ (\`data/$ID.enc\`)"; HEAD="เพิ่มรายงาน"; else LINE="- 🔄 อัปเดตรายงาน (\`data/$ID.enc\`)"; HEAD="อัปเดตรายงาน"; fi
python3 - "$TS" "$HEAD" "$LINE" <<'PY'
import sys
ts, head, line = sys.argv[1:4]
p = 'CHANGELOG.md'; s = open(p, encoding='utf-8').read()
i = s.index('\n## ') + 1
open(p, 'w', encoding='utf-8').write(s[:i] + f'## {ts} · __HASH__ · {head}\n{line}\n\n' + s[i:])
PY

# ---- 4) ตรวจก่อน commit: แตะได้แค่ data/ + CHANGELOG · ไม่มีรหัสหลุด ----
git add -A
bad="$(git diff --cached --name-only | grep -v -E '^(data/[0-9a-f]{12}\.enc|data/manifest\.enc|CHANGELOG\.md)$' || true)"
[ -z "$bad" ] || { git reset -q; die "มีไฟล์อื่นปน (ห้ามเผยแพร่ผ่านสคริปต์นี้):
$bad"; }
if git diff --cached --name-only | xargs grep -lI -F "$REPORTS_PASS" >/dev/null 2>&1; then git reset -q; die "เจอรหัสผ่านในไฟล์ที่จะ commit"; fi

if [ "$DRY" = 1 ]; then
  echo "• dry-run: ไม่ commit/push · ไฟล์ที่จะขึ้น:"; git diff --cached --stat; git reset -q
  echo "  (คืนสภาพ: git checkout -- . ใน repo · ไฟล์ดิบใน reports-src อัปเดตไปแล้ว)"; exit 0
fi

# ---- 5) commit + เติม hash + push ----
G=(git -c user.name=faceadvance -c user.email=faceadvances.th@gmail.com)
"${G[@]}" commit -q -m "data: ${HEAD} ${ID}

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
H="$(git rev-parse --short HEAD)"
sed -i '' "s/ · __HASH__ · / · \`$H\` · /" CHANGELOG.md
git add CHANGELOG.md
"${G[@]}" commit -q -m "docs(changelog): เติม commit hash ($TS)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -q
python3 - "$SRC" <<'PY'
import json, os, sys
src = sys.argv[1]; p = json.load(open(os.path.join(src, '.pending.json')))
pp = os.path.join(src, '.published.json'); pub = json.load(open(pp)) if os.path.exists(pp) else {}
pub[p['slug']] = p['digest']; json.dump(pub, open(pp, 'w'), indent=1); os.remove(os.path.join(src, '.pending.json'))
PY
echo "✓ push แล้ว · commit $H"

# ---- 6) รอจนเว็บจริงตรง (สูงสุด ~5 นาที) ----
for i in $(seq 1 20); do
  ok=1
  for f in "data/$ID.enc" data/manifest.enc; do
    [ "$(shasum -a 256 "$f" | cut -c1-16)" = "$(curl -s "$SITE/$f?nc=$RANDOM$i" | shasum -a 256 | cut -c1-16)" ] || ok=0
  done
  [ $ok = 1 ] && { echo "✓ เว็บจริงอัปเดตแล้ว → $SITE/?r=$SLUG"; exit 0; }
  sleep 15
done
die "push แล้วแต่เว็บจริงยังไม่ตรงภายใน 5 นาที — เช็ก: gh api repos/faceadvance/face-advance-reports/pages/builds/latest"
