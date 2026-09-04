#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${GITHUB_WORKSPACE:-$PWD}"
N="233108530344407544527637656910680524145619812480305449042948611968495918245135782867888369318577116418213919268572658314913060672626911354027609793166341626693946596196427744273886601876896313468704059066746903123910748277606548649151920812699309766587514735456594993207"
QMIN=1073322392
QMAX=1073332392
OUT="$ROOT/campaign"
mkdir -p "$ROOT/downloaded" "$ROOT/extracted" "$OUT/work"

pack_checkpoint() {
    set +e
    cd "$ROOT"
    find campaign -type f -printf '%P\t%s\n' | sort > campaign/work/files.tsv 2>/dev/null
    tar --zstd --ignore-failed-read -cf rsa270-fast3-checkpoint.tar.zst campaign 2>campaign/work/pack.stderr
    sha256sum rsa270-fast3-checkpoint.tar.zst > rsa270-fast3-checkpoint.tar.zst.sha256 2>/dev/null
    ls -lh rsa270-fast3-checkpoint.tar.zst* 2>/dev/null
}
trap pack_checkpoint EXIT

cd "$ROOT"
gh run download 33818693904 --repo "$GITHUB_REPOSITORY" \
    --name rsa270-cado-built-tools --dir downloaded
ACTUAL=$(sha256sum downloaded/rsa270-cado-built-tools.tar.zst | cut -d' ' -f1)
test "$ACTUAL" = "0f5238567ad06606813bd3d9306d7f54ab4e61426747e948cb84466bd70a18af"
tar --zstd -xf downloaded/rsa270-cado-built-tools.tar.zst -C extracted
POLY=$(find extracted -type f -name 'RSA-270-best-cado.poly' -print -quit)
test -n "$POLY"
cp "$POLY" "$OUT/RSA-270.poly"
rm -rf "$ROOT/cado-nfs-modern"
mv "$ROOT/extracted/rsa270-tool-bundle/cado" "$ROOT/cado-nfs-modern"
CADO="$ROOT/cado-nfs-modern"
BUILD=$(find "$CADO/build" -mindepth 1 -maxdepth 1 -type d -print -quit)
test -n "$BUILD"
printf '%s\n' "$CADO" > "$BUILD/source-location.txt"
"$BUILD/sieve/las" -version | tee "$OUT/work/original-las-version.txt"

sed -i 's/^#define SIZEOF_P_R_VALUES 4$/#define SIZEOF_P_R_VALUES 8/' "$CADO/utils/typedefs.h"
test "$(awk '/^#define SIZEOF_P_R_VALUES/{print $3}' "$CADO/utils/typedefs.h)" = 8
touch "$CADO/utils/typedefs.h"
/usr/bin/time -v -o "$OUT/work/rebuild.time" \
    make -C "$BUILD" -j4 freerel/fast makefb/fast las/fast \
    > "$OUT/work/rebuild.stdout" 2> "$OUT/work/rebuild.stderr"
sha256sum "$BUILD/sieve/freerel" "$BUILD/sieve/makefb" "$BUILD/sieve/las" \
    | tee "$OUT/work/64bit-binaries.sha256"

python3 - <<'PY'
from pathlib import Path
N=int("233108530344407544527637656910680524145619812480305449042948611968495918245135782867888369318577116418213919268572658314913060672626911354027609793166341626693946596196427744273886601876896313468704059066746903123910748277606548649151920812699309766587514735456594993207")
c=[364247333275683342472365165550476120730693693328818157502991593984,1153973715089888191946389898261544454239234565820467806984,-236435216210702701902151548470267342947180119662,-44103587181491086831987630081373613537,4057688710924064290332793594,118153186763991104,240240]
y0=-99499021054511834692076135344701239177544641
y1=6382870559300260766501
R=sum(c[i]*(-y0)**i*y1**(6-i) for i in range(7))
assert R==N
Path('campaign/work/resultant-verification.txt').write_text('resultant_equals_N=true\nresultant_quotient=1\n')
PY

"$BUILD/sieve/freerel" \
    -poly "$OUT/RSA-270.poly" -lpb0 38 -lpb1 39 \
    -pmin 1073741800 -pmax 1073741950 \
    -out "$OUT/work/freerel-64bit-check.gz" \
    > "$OUT/work/freerel-check.stdout" 2> "$OUT/work/freerel-check.stderr"
gzip -t "$OUT/work/freerel-64bit-check.gz"

/usr/bin/time -v -o "$OUT/work/makefb.time" \
    "$BUILD/sieve/makefb" \
      -poly "$OUT/RSA-270.poly" -lim 2146644785 -maxbits 18 \
      -out "$OUT/work/c270.roots1.gz" -side 1 -t 4 \
      > "$OUT/work/makefb.stdout" 2> "$OUT/work/makefb.stderr"
gzip -t "$OUT/work/c270.roots1.gz"
sha256sum "$OUT/work/c270.roots1.gz" | tee "$OUT/work/c270.roots1.gz.sha256"
free -h | tee "$OUT/work/memory-before-las.txt"

"$BUILD/sieve/las" \
    -poly "$OUT/RSA-270.poly" \
    -lim0 1071225238 -lim1 2146644785 \
    -lpb0 38 -lpb1 39 -mfb0 109 -mfb1 120 \
    -ncurves0 28 -ncurves1 31 -I 18 \
    -q0 "$QMIN" -q1 "$QMAX" -sqside 1 \
    -fb1 "$OUT/work/c270.roots1.gz" -print-todo-list -t 4 \
    > "$OUT/work/todo-all.txt" 2> "$OUT/work/todo.stderr"
grep '^1 ' "$OUT/work/todo-all.txt" | head -10 > "$OUT/work/todo.txt"
test "$(wc -l < "$OUT/work/todo.txt")" -eq 10
cat "$OUT/work/todo.txt"

set +e
/usr/bin/time -v -o "$OUT/work/las.time" \
    timeout --signal=INT --kill-after=60s 15000s \
    "$BUILD/sieve/las" \
      -poly "$OUT/RSA-270.poly" \
      -lim0 1071225238 -lim1 2146644785 \
      -lpb0 38 -lpb1 39 -mfb0 109 -mfb1 120 \
      -ncurves0 28 -ncurves1 31 -I 18 \
      -sqside 1 -fb1 "$OUT/work/c270.roots1.gz" \
      -todo "$OUT/work/todo.txt" -out "$OUT/work/relations.gz" \
      -t 4 -production -stats-stderr -job-memory 13 -bkmult 1.1 \
      > "$OUT/work/las.stdout" 2> "$OUT/work/las.stderr"
LAS_RC=$?
echo "$LAS_RC" > "$OUT/work/las.rc"
gzip -t "$OUT/work/relations.gz"
set -e

python3 - <<'PY'
import gzip,json,math,pathlib
N=int("233108530344407544527637656910680524145619812480305449042948611968495918245135782867888369318577116418213919268572658314913060672626911354027609793166341626693946596196427744273886601876896313468704059066746903123910748277606548649151920812699309766587514735456594993207")
c=[364247333275683342472365165550476120730693693328818157502991593984,1153973715089888191946389898261544454239234565820467806984,-236435216210702701902151548470267342947180119662,-44103587181491086831987630081373613537,4057688710924064290332793594,118153186763991104,240240]
y0=-99499021054511834692076135344701239177544641
y1=6382870559300260766501
todos=[]
for line in pathlib.Path('campaign/work/todo.txt').read_text().splitlines():
    z=line.split(); todos.append((int(z[0]),int(z[1]),int(z[2])))
lines=[]
p=pathlib.Path('campaign/work/relations.gz')
if p.exists(): lines=[x.strip() for x in gzip.open(p,'rt',errors='strict') if x.strip() and not x.startswith('#')]
rows=[]; hits=[]
for line in lines:
    h=line.split(':'); a,b=map(int,h[0].split(','))
    rf=[int(x,16) for x in h[1].split(',') if x]
    af=[int(x,16) for x in h[2].split(',') if x]
    rn=abs(y1*a+y0*b)
    an=abs(sum(c[i]*a**i*b**(6-i) for i in range(7)))
    matches=[{'q':q,'rho':rho} for side,q,rho in todos if q in af and (a-b*rho)%q==0 and sum(c[i]*pow(rho,i,q) for i in range(7))%q==0]
    gcds=sorted({math.gcd(x,N) for x in set(rf+af) if 1<math.gcd(x,N)<N})
    for g in gcds: hits.append({'p':str(g),'q':str(N//g),'verified':g*(N//g)==N})
    rows.append({'line':line,'rational_exact':rn==math.prod(rf),'algebraic_exact':an==math.prod(af),'matching_q_roots':matches,'gcds':[str(x) for x in gcds],'valid':rn==math.prod(rf) and an==math.prod(af) and len(matches)==1})
out={'N':str(N),'relations':len(rows),'valid_relations':sum(r['valid'] for r in rows),'all_relations_valid':bool(rows) and all(r['valid'] for r in rows),'verified_hits':hits,'rows':rows}
pathlib.Path('campaign/work/exact-verification.json').write_text(json.dumps(out,indent=2))
print(json.dumps({k:v for k,v in out.items() if k!='rows'},indent=2))
PY

exit "$LAS_RC"
