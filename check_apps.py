# -*- coding: utf-8 -*-
"""Checks that ask what a user would ask, not what a programmer would."""
import asyncio, sys, json
from playwright.async_api import async_playwright
CHROME="/home/claude/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome"

UG=["home","register","clinic","intraop","pacu","ward","records","practical","eval",
    "dashboard","survey","feedback","announcements","elearning","course-ref"]
PG=["home","register","pg-clinic","pg-intraop","pg-pacu","pg-ward","records","practical",
    "eval","dashboard","survey","announcements","elearning","course-ref"]

SEED = [
 {"id":"s1","type":"intraop","status":"submitted","studentId":"443","studentName":"A","caseNo":"1","patientMRN":"11"},
 {"id":"s2","type":"pacu","status":"submitted","studentId":"443","studentName":"A","caseNo":"2","patientMRN":"22"},
 {"id":"s3","type":"clinic","status":"submitted","studentId":"444","studentName":"B","caseNo":"1","patientMRN":"33"},
 {"id":"s4","type":"ward","status":"draft","studentId":"444","studentName":"B","caseNo":"2","patientMRN":"44"},
 {"type":"case_review","id":"r1","caseId":"s1","status":"awaiting_release","total":56},
 {"type":"evaluation","id":"e1","caseId":"s2","status":"approved","finalMark":4},
]

OVERFLOW="""(sid)=>{document.querySelectorAll('.screen').forEach(e=>e.classList.remove('active'));
 const s=document.getElementById('screen-'+sid); if(!s)return{missing:1}; s.classList.add('active');
 document.querySelectorAll('.course-topic-content').forEach(d=>d.classList.add('open'));
 const vw=document.documentElement.clientWidth; let n=0,mx=0;
 s.querySelectorAll('*').forEach(el=>{const r=el.getBoundingClientRect(); if(!r.width&&!r.height)return;
  const o=Math.round(r.right-vw); if(o>1){n++;mx=Math.max(mx,o);}});
 return {n,mx};}"""

HANDLERS="""()=>{const bad=[],seen=new Set();
 document.querySelectorAll('[onclick],[oninput],[onchange]').forEach(el=>{
  ['onclick','oninput','onchange'].forEach(a=>{const c=el.getAttribute(a); if(!c)return;
   /* only bare calls: skip obj.method(...) and keywords, or the check cries
      wolf on getElementById and classList.toggle every run */
   [...c.matchAll(/(^|[^.\\w$])([A-Za-z_$][\\w$]*)\\s*\\(/g)].map(m=>m[2]).forEach(n=>{
    if(['if','for','while','return','typeof','this','alert','confirm','parseInt','parseFloat',
        'String','Number','JSON','setTimeout','event','document','window','Event','function','catch','switch'].includes(n))return;
    if(seen.has(n))return; seen.add(n);
    if(typeof window[n]!=='function') bad.push(n);});});});
 return bad;}"""

# Does every number agree with the list it opens?
COUNTERS="""()=>{
 const n=id=>+document.getElementById(id).textContent;
 const shown=()=> (document.getElementById('dash-list').innerText.match(/MRN /g)||[]).length;
 const out={};
 [['tomark','dash-pending-count'],['done','dash-evaluated-count'],['drafts','dash-draft-count']]
   .forEach(([f,id])=>{ setDashFilter('all'); const c=n(id); setDashFilter(f);
     out[f]={counter:c, listed:shown(), agree:c===shown()}; setDashFilter('all'); });
 return out;}"""

# Is anything on screen showing raw escape codes or an undefined?
TEXT="""()=>{
 /* innerText only sees what is currently visible, so a fault inside a closed
    modal escaped this check. Read the rendered text of every element instead,
    hidden or not - the user will open that modal eventually. */
 const t=[...document.querySelectorAll('button,div,span,label,p,h1,h2,h3')]
   .map(e=>e.textContent).join(' ');
 return {escapes:/\\\\u[0-9A-Fa-f]{4}|U000[0-9A-F]{5}/.test(t),
         undef:/\\bundefined\\b/.test(document.body.innerText),
         nan:/\\bNaN\\b/.test(document.body.innerText)};}"""

# Are modals real children of body, so no hidden parent can swallow them?
MODALS="""()=>[...document.querySelectorAll('[id$=-modal],#sup-welcome,#class-gate')]
 .filter(m=>m.parentElement!==document.body).map(m=>m.id)"""

async def run(path, screens, label):
    async with async_playwright() as p:
        br=await p.chromium.launch(executable_path=CHROME,args=["--no-sandbox"])
        errs=[]; pg=await br.new_page(viewport={"width":360,"height":740})
        pg.on("pageerror",lambda e:errs.append(str(e)[:140]))
        await pg.add_init_script("try{localStorage.setItem('medi045_class_code','X');"
                                 "localStorage.setItem('medi045_sup_welcomed','1');}catch(e){}")
        await pg.goto("file://"+path)
        await pg.add_style_tag(content="*{animation:none!important;transition:none!important}")
        await pg.wait_for_timeout(1000)
        await pg.evaluate("(seed)=>{seed.forEach(r=>records.push(r));"
                          "document.querySelectorAll('.screen').forEach(e=>e.classList.remove('active'));"
                          "document.getElementById('screen-dashboard').classList.add('active');"
                          "renderDashboard();}", SEED)
        fails=[]
        c=await pg.evaluate(COUNTERS)
        for k,v in c.items():
            if not v['agree']:
                fails.append("counter '%s' says %d but its filter lists %d" % (k, v['counter'], v['listed']))
        for sid in screens:
            r=await pg.evaluate(OVERFLOW,sid); await pg.wait_for_timeout(25); r=await pg.evaluate(OVERFLOW,sid)
            if r.get('missing'): fails.append("screen %s missing" % sid)
            elif r['n']: fails.append("screen %s overflows by %dpx" % (sid, r['mx']))
        h=await pg.evaluate(HANDLERS)
        if h: fails.append("handlers with no function: %s" % h)
        t=await pg.evaluate(TEXT)
        if t['escapes']: fails.append("raw escape codes visible on screen")
        if t['undef']:   fails.append("the word 'undefined' visible on screen")
        if t['nan']:     fails.append("'NaN' visible on screen")
        m=await pg.evaluate(MODALS)
        if m: fails.append("modals not direct children of body: %s" % m)
        real=[e for e in errs if 'fetch' not in e.lower() and '403' not in e]
        if real: fails.append("javascript errors: %s" % real)
        print(("PASS  " if not fails else "FAIL  ")+label)
        for f in fails: print("        - "+f)
        await br.close()
        return not fails

async def main():
    ok = True
    ok &= await run(sys.argv[1], UG, "undergraduate")
    ok &= await run(sys.argv[2], PG, "postgraduate")
    print()
    print("ALL CHECKS PASSED" if ok else "CHECKS FAILED")
    sys.exit(0 if ok else 1)
asyncio.run(main())
