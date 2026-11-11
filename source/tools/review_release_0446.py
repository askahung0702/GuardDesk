"""Self-review of the HTML mail attachment change and exact internal trial."""
import ast,json,re,shutil,sys,zipfile
from PyInstaller.archive.readers import CArchiveReader
from review_release_0441 import ROOT,sha,read
sys.path.insert(0,str(ROOT))
VERSION='0.4.46'

def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True);logs={}
    for name,count in [('html-mail-unit-0446.txt',30),('html-mail-audit-rollup-0446.txt',4),('html-mail-index-regression-0446.txt',15)]:
        p=ROOT/'runtime'/name;s=p.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n');m=re.search(r'Ran (\d+) tests in ([\d.]+)s',s)
        assert m and int(m[1])==count and '\nOK\n' in s and 'FAILED (' not in s,s[-2000:]
        logs[name]={'tests':count,'passed':True,'seconds':float(m[2]),'sha256':sha(p)}
    capacity=json.loads(re.search(r'HTML_ATTACHMENT_CAPACITY (\{[^\n]+\})',(ROOT/'runtime/html-mail-unit-0446.txt').read_text(encoding='utf-8-sig',errors='replace'))[1])
    assert capacity['devices']==250 and capacity['charts']==8 and capacity['graph_json_bytes']<=2800000
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()};smoke=read(ROOT/'evidence/packaged-smoke.json')
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==actual['GuardDesk.exe'] and smoke['gui_sha256']==actual['GuardDeskAgent.exe']
    browsers={}
    for stem in ('mail-reports','audit-search'):
        value=read(ROOT/f'evidence/{stem}-browser-{VERSION}.json')
        assert value['passed'] and value['frozen_server_used'] and value['version']==VERSION and value['exe_sha256']==actual['GuardDesk.exe'] and not value['page_errors'];browsers[stem]=value
    mail=browsers['mail-reports'];assert not mail['live_mail_sent'] and not mail['live_credentials_read'] and not mail['offline_http_requests']
    sample=ROOT/f'evidence/mail-attachment-example-{VERSION}.html';assert sha(sample)==mail['downloaded_attachment_sha256'] and sample.stat().st_size==mail['downloaded_attachment_bytes']
    text=sample.read_text(encoding='utf-8');assert text.count('data:image/png;base64,')==8 and 'cid:' not in text and '<script' not in text and 'PC-249' in text
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');modules=[]
    for p in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if p.stem=='__init__' else 'guarddesk.'+p.stem
        if name in archive.toc:assert archive.extract(name)==compile(p.read_bytes(),str(p),'exec'),name;modules.append(name)
    for area in ('static','windows'):
        for p in (ROOT/'guarddesk'/area).rglob('*'):
            if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk'/area/p.relative_to(ROOT/'guarddesk'/area)).read_bytes(),p
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,total=source_files(app);assert verified==actual
    previous=read(ROOT/'evidence/security/0.4.45/requirements-review.json');prior=previous['prior_archives_unchanged']
    prior.update({'GuardDesk-0.4.45-windows-x64.zip':'1752ea99c9a0ea0be013700b9ef1a57fdf2baa385b26e50bad7e6006ac134bdd','GuardDesk-0.4.45-source.zip':'b3777e34730901cab15394a9959e72a6004705a9c941f027bfbea714cc6578c2'})
    for name,digest in prior.items():assert sha(ROOT/'dist'/name)==digest,name
    allowed={'guarddesk/__init__.py','guarddesk/mail_reports.py','guarddesk/static/mail_reports_ui.js','guarddesk/static/index.html'};changed=set();unchanged=[]
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.45-source.zip') as z:
        for name in z.namelist():
            if name.startswith(('guarddesk/','browser-extension/')) or name in ('requirements.txt','requirements-build.txt','app.py','tools/GuardDesk.spec','Setup-Management.cmd','Install-Endpoint.cmd','Install-Endpoint.ps1','Uninstall-Endpoint.cmd','Start-GuardDesk.ps1','Start-Remote.cmd','Diagnose-Remote.cmd'):
                assert (ROOT/name).is_file(),name
                if z.read(name)!=(ROOT/name).read_bytes():changed.add(name)
                else:unchanged.append(name)
        original=ast.parse(z.read('guarddesk/mail_reports.py'))
    assert changed==allowed,changed
    for name in ('guarddesk/audit_search_index.py','guarddesk/audit_reports.py','guarddesk/store.py','guarddesk/server.py','guarddesk/native_installer.py','guarddesk/event_storage.py','guarddesk/agent.py','guarddesk/updater_maintenance.py','guarddesk/updater_refresh.py'):
        assert name in unchanged,name
    functions=lambda tree:{n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
    before=functions(original);after=functions(ast.parse((ROOT/'guarddesk/mail_reports.py').read_bytes()))
    assert before.keys()==after.keys() and {n for n in before if before[n]!=after[n]}=={'render','send'}
    signatures=read(folder/'signatures.json')
    for value in signatures:assert sha(ROOT/value['path'])==value['sha256']
    report={'version':VERSION,'status':'unsigned_internal_trial','passed_with_gaps':True,'review_type':'developer_self_review_not_independent',
        'requirements':['SEC-01','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-04'],'lessons':['GD-005','GD-014','GD-017','GD-018','GD-020','GD-021','GD-023'],
        'change':'Plain Text mail body with date/opening instructions; one UTF-8 self-contained HTML fileAttachment, isInline=false, embedded PNGs; preview/download share render',
        'controls':['Existing computer-ID aggregation/name display, all-device charts/table incl zero, top20 and Taipei previous-day semantics retained','HTML escaping plus static document CSP: no scripts, external requests, forms/base; images only data PNG; no CID dependency','Existing 2.8-million-byte final Graph JSON cap after both Base64 layers; explicit failure, no truncation; original 1.8-million-byte chart cap retained','Existing fixed TLS hosts/Graph permission and recipient settings; no new destinations or privileges','MailWorker/config/token/queue/retry/snapshot definitions AST-identical to 45; unknown outcomes still never auto retry','Only four runtime files changed; collector, storage, index, authorization, installer/updater/remote/custom engines byte-identical to sealed 45 sources'],
        'threat_analysis':{'assets':'Sensitive computer activity aggregates and existing M365 credentials','boundary':'Admin-authorized rollup snapshot -> static escaped attachment -> existing configured MIS recipients over Graph TLS','risks':'HTML active content/external resource leaks, CID dependency, body exposing full report, encoded-size overflow, duplicate sends; controlled by escaping/static CSP/inline data, brief Text body, actual serialized cap, unchanged bounded queue/unknown-state rules','retention':'No new persistent server report store; preview/download files are created only on MIS request, sent mail remains subject to existing company retention'},
        'tests':{'scoped_unique_cases':49,'logs':logs,'full_suite_rerun':False,'previous_full_suite':{'version':'0.4.45','tests':494,'not_counted_as_this_version':True},'scope_reason':'Only mail rendering/send envelope and mail UI change; scheduling/auth/queue/rollups and all other engines byte-identical or AST-identical. Scoped mail, rollup, search regression plus final frozen audit/mail and full packaged smoke were run.'},
        'capacity_fixture':capacity,'frozen_browsers':browsers,'sample_sha256':sha(sample),'sample_is_synthetic':True,'compiled_modules_equal_source':modules,'application_files':len(actual),'application_bytes':total,'critical_sources_unchanged':unchanged,'source_files':{n:sha(ROOT/n) for n in sorted(allowed)},'prior_archives_unchanged':prior,'signatures':signatures,
        'development_findings':{'initial_capacity_log_sha256':sha(ROOT/'runtime/html-mail-unit-0446-initial-capacity.txt'),'capacity':'A new 1000-active-Chinese-device fixture exceeded the existing 1.8MB image cap; assumption of always fitting was corrected, no cap weakened. Target 250 case and encoded-overflow rejection then passed.','caption_assertion_log_sha256':sha(ROOT/'runtime/html-mail-browser-caption-check-0446.txt'),'visual_copy':'Preview visual review found a legacy inline-mail footer. Initial replacement used an incorrect literal and the added browser assertion caught it. Exact source match then corrected; the final asset-only build copied this JS and regenerated public manifest while preserving existing EXEs. Mail/audit browsers and packaged smoke then reran on the final complete tree; initial tree evidence retained under runtime.'},
        'gaps':['No live M365 credential read, email sent, tenant delivery or attachment-policy acceptance performed','Company Windows/Defender lifecycle, signing, full SBOM/vulnerability and independent review remain incomplete','1000-device structural cap does not guarantee all image/name combinations fit; explicit capacity failure remains','Prior installer health/cloud-scan delay and GD-006 generic source-error gap remain outside scope'],
        'office_server_or_endpoints_changed':False,'live_mail_sent':False}
    links=0
    for name in ('README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/66-daily-mail-html-attachment-0.4.46.md'):
        p=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            resolved=(p.parent/target.split('#')[0]).resolve()
            assert resolved.exists() or resolved==(folder/'requirements-review.json').resolve(),(name,target)
            links+=1
    report['document_links_checked']=links;(folder/'requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    print(json.dumps({'passed':True,'scoped_tests':49,'compiled_modules':len(modules),'document_links':links,'application_files':len(actual),'live_mail_sent':False,'office_deployed':False}))

if __name__=='__main__':main()
