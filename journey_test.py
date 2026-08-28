import asyncio, json
from playwright.async_api import async_playwright
CHROME="/home/claude/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome"

async def main():
    fails=[]
    async with async_playwright() as p:
        br=await p.chromium.launch(executable_path=CHROME,args=["--no-sandbox"])
        errs=[]
        pg=await br.new_page(viewport={"width":390,"height":840})
        pg.on("pageerror",lambda e:errs.append(str(e)[:160]))
        pg.on("dialog", lambda d: asyncio.ensure_future(d.accept()))
        # server unreachable for me, so simulate it accepting everything
        await pg.route("**/*workers.dev/**", lambda r: r.fulfill(
            status=200, content_type="application/json", body="[]"))
        await pg.goto("file:///home/claude/work/journey.html")
        await pg.wait_for_timeout(1200)

        # ---- STEP 1: the class-code gate on a fresh device
        s1=await pg.evaluate("""()=>{const g=document.getElementById('class-gate');
          return {shown:getComputedStyle(g).display!=='none'};}""")
        if not s1['shown']: fails.append("1 class-code gate did not appear on a fresh device")
        await pg.evaluate("""()=>{document.getElementById('class-gate-input').value='MEDI045-UG-DU1C-KANA-LHBP';
          submitClassGate();}""")
        await pg.wait_for_timeout(600)
        s1b=await pg.evaluate("()=>getComputedStyle(document.getElementById('class-gate')).display")
        if s1b!='none': fails.append("1 gate did not close after a valid code")

        # ---- STEP 2: register
        await pg.evaluate("""()=>{goto('screen-register');
          const set=(id,v)=>{const e=document.getElementById(id); if(e){e.value=v;}};
          set('reg-name','Test Student'); set('reg-id','999001'); set('reg-group','A1');}""")
        await pg.wait_for_timeout(200)
        s2=await pg.evaluate("""()=>{ try{ saveProfile(); }catch(e){ return {err:String(e)}; }
          return {profile: !!studentProfile, name: studentProfile&&studentProfile.name,
                  id: studentProfile&&studentProfile.universityId};}""")
        if not s2.get('profile'): fails.append("2 registration did not save a profile: %s"%s2)

        # ---- STEP 3: fill a case and SAVE AS DRAFT
        await pg.evaluate("()=>goto('screen-intraop')"); await pg.wait_for_timeout(300)
        filled=await pg.evaluate("""()=>{let n=0;
          document.querySelectorAll('#screen-intraop input,#screen-intraop select,#screen-intraop textarea').forEach(el=>{
            if(['hidden','file','checkbox','radio'].includes(el.type)) return;
            /* readonly fields are auto-filled identity - a student cannot type
               in them, and overwriting them here made the test orphan its own
               draft and blame the app */
            if(el.readOnly || el.disabled) return;
            if(el.tagName==='SELECT'){ if(el.options.length>1){el.selectedIndex=1;n++;} return;}
            if(el.type==='date'){ el.value='2026-08-28'; n++; return;}
            if(el.type==='number'){ el.value='7'; n++; return;}
            el.value='J'+(++n);});
          document.getElementById('io-mrn').value='900001';
          document.getElementById('io-case-no').value='1';
          if (typeof autoFillProfile === 'function') autoFillProfile();
          return n;}""")
        await pg.evaluate("()=>saveDraft_io()"); await pg.wait_for_timeout(500)
        s3=await pg.evaluate("""()=>{const d=records.filter(r=>r.type==='intraop'&&r.status==='draft');
          const keys=d.length?Object.keys(d[0]).filter(k=>d[0][k]!==''&&d[0][k]!=null).length:0;
          return {drafts:d.length, fieldsKept:keys, id:d.length?d[0].id:null};}""")
        if s3['drafts']!=1: fails.append("3 draft was not saved (%s)"%s3)
        elif s3['fieldsKept']<30: fails.append("3 draft kept only %d fields"%s3['fieldsKept'])

        # ---- STEP 4: leave, come back, RESUME the draft
        await pg.evaluate("()=>goto('screen-home')"); await pg.wait_for_timeout(200)
        s4=await pg.evaluate("""(id)=>{ try{ continueDraft(id); }catch(e){ return {err:String(e)}; }
          const mrn=document.getElementById('io-mrn');
          return {mrnRestored: mrn? mrn.value:null,
                  monitorsRestored: (document.getElementById('c-monitors')||{}).value};}""", s3['id'])
        if s4.get('mrnRestored')!='900001':
            fails.append("4 resuming the draft did not restore the MRN (%s)"%s4)

        # ---- STEP 5: SUBMIT
        await pg.wait_for_timeout(300)
        await pg.evaluate("()=>submit_io()"); await pg.wait_for_timeout(900)
        s5=await pg.evaluate("""()=>{const sub=records.filter(r=>r.type==='intraop'&&r.status==='submitted');
          const dr=records.filter(r=>r.type==='intraop'&&r.status==='draft');
          window.__draftDetail = dr.map(d=>({id:d.id, mrn:d.patientMRN, sid:d.studentId}));
          return {submitted:sub.length, draftsLeft:dr.length,
                  mrn:sub.length?sub[0].patientMRN:null,
                  fields:sub.length?Object.keys(sub[0]).filter(k=>sub[0][k]!==''&&sub[0][k]!=null).length:0};}""")
        if s5['submitted']!=1: fails.append("5 case was not submitted (%s)"%s5)
        if s5['draftsLeft']!=0:
            detail = await pg.evaluate("()=>window.__draftDetail")
            fails.append("5 the draft survived submission: %s"%detail)
        if s5['mrn']!='900001': fails.append("5 submitted case lost its MRN (%s)"%s5)

        # ---- STEP 6: the supervisor sees it and can mark it
        s6=await pg.evaluate("""()=>{ setStaffToken('S'); evalUnlocked=true;
          document.querySelectorAll('.screen').forEach(e=>e.classList.remove('active'));
          document.getElementById('screen-dashboard').classList.add('active');
          renderDashboard();
          const t=document.getElementById('dash-list').innerText;
          return {visibleToSupervisor:/900001/.test(t),
                  toMark:+document.getElementById('dash-pending-count').textContent};}""")
        if not s6['visibleToSupervisor']: fails.append("6 the submitted case is not visible to the supervisor")
        if s6['toMark']<1: fails.append("6 'to mark' did not count the new case (%s)"%s6)

        # ---- STEP 7: mark it, 60 auto + 40 judgment
        cid=await pg.evaluate("()=>records.filter(r=>r.type==='intraop'&&r.status==='submitted')[0].id")
        s7=await pg.evaluate("""(id)=>{ openScoreReview(String(id));
          const auto=_autoTotalNow();
          setReviewPage(2);
          ['reasoning','viva','prof','reflect'].forEach((d,i)=>{const el=document.getElementById('sup-'+d);
            el.value=[12,8,7,6][i]; el.dispatchEvent(new Event('input'));});
          finaliseReview();
          const rev=records.filter(r=>r.type==='case_review')[0];
          return {autoScore:auto.scaled, autoMax:_reviewScore?60:60,
                  saved:!!rev, total:rev&&rev.total, status:rev&&rev.status,
                  studentCopy: records.some(r=>r.type==='case_mark')};}""", cid)
        if not s7['saved']: fails.append("7 the mark was not saved (%s)"%s7)
        if s7.get('status')!='awaiting_release': fails.append("7 mark status is %s, expected awaiting_release"%s7.get('status'))
        if s7.get('studentCopy'): fails.append("7 a student copy was created before the admin released it")

        # ---- STEP 8: admin releases
        s8=await pg.evaluate("""()=>{ renderReleaseQueue();
          const waiting=_marksAwaiting().length;
          releaseMark(_marksAwaiting()[0].caseId);
          const mark=records.filter(r=>r.type==='case_mark')[0];
          return {wasWaiting:waiting, released:!!mark, total:mark&&mark.total,
                  queueNow:_marksAwaiting().length};}""")
        if s8['wasWaiting']!=1: fails.append("8 the release queue did not hold the mark (%s)"%s8)
        if not s8['released']: fails.append("8 releasing did not create the student's copy (%s)"%s8)
        if s8['queueNow']!=0: fails.append("8 the queue did not empty after release (%s)"%s8)

        real=[e for e in errs if 'fetch' not in e.lower() and '403' not in e]
        if real: fails.append("javascript errors during the journey: %s"%real)

        print("auto score for a fully filled case: %s/60" % s7.get('autoScore'))
        print("final mark after judgment marks   : %s/100" % s7.get('total'))
        print()
        if fails:
            print("JOURNEY FAILED")
            for f in fails: print("   - "+f)
        else:
            print("JOURNEY PASSED  (register -> draft -> resume -> submit -> supervisor -> mark -> release)")
        await br.close()
asyncio.run(main())
