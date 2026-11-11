"""Separate receipt, collector reports and actual enforcement evidence."""
import hashlib
import json
import time
import math


def mapping(value):return value if isinstance(value,dict) else {}

def timestamp(value):return value if type(value) in (int,float) and math.isfinite(value) and value>=0 else 0


def application_signature(policy):
    # Preserve the existing worker signature, including its serialization.
    return hashlib.sha256(json.dumps({'audit':policy['application_audit'],'control':policy['application_control']},sort_keys=True).encode()).hexdigest()


def progress(device,effective):
    policy=effective['body'];assets=mapping(device.get('inventory'));collectors=mapping(assets.get('collectors'))
    received=bool(device.get('policy_received'));online=time.time()-device['last_seen']<90
    sources=effective['field_sources'];rows=[]
    def add(key,name,desired,state,reason,at=None):
        source_key={'file_audit':'file_audit.enabled','file_access_filter':'file_audit.exclude_paths','application_control':'application_control.enabled'}.get(key,key)
        source=effective.get('setting_sources',{}).get(source_key,sources['file_audit'] if key=='file_access_filter' else sources[key])
        rows.append({'key':key,'name':name,'desired':desired,'source':source['name'],
                     'published_version':effective['version'],'received':received,'state':state,
                     'reason':reason,'reported_at':at,'hardware_tested':False})
    usb=device.get('native_usb')
    if not online:state,reason='offline','端點離線，等待重新連線'
    elif not usb:state,reason='pending','尚未收到 USB 背景元件回報'
    elif usb.get('status')=='failed':state,reason='failed',usb.get('error') or 'USB 設定失敗'
    elif not usb.get('fresh') or not usb.get('matches_policy') or usb.get('version')!=effective['version']:state,reason='pending','回報過舊或設定版本不符'
    elif usb.get('verified_readback'):state,reason='replug','元件回報設定讀回相符；需重插並實測'
    else:state,reason='pending','尚無設定讀回相符的證據'
    add('usb_mode','USB 儲存',policy['usb_mode'],state,reason,usb.get('received') if usb else None)
    ext=mapping(device.get('extended_status'));fresh=0<=time.time()-timestamp(ext.get('received'))<120
    matches=ext.get('applied_signature')==application_signature(policy)
    for key,name,desired in [('application_audit','程式啟停稽核',policy['application_audit']),('application_control','程式執行管制',policy['application_control']['enabled'])]:
        if not online:state,reason='offline','端點離線'
        elif ext.get('status')=='failed':state,reason='failed',ext.get('error') or '背景元件設定失敗'
        elif not fresh or not matches:state,reason='pending','尚無目前設定的元件回報；舊元件需更新後回報'
        elif key=='application_audit' and mapping(ext.get('process_audit')).get('status')=='failed':state,reason='failed','程序日誌收集失敗'
        elif ext.get('status')=='configured':state,reason='reported','元件回報設定完成；實際執行效果仍需測試'
        else:state,reason='pending','等待背景元件設定結果'
        add(key,name,desired,state,reason,ext.get('received'))
    for key,name,desired,report in [('browser_audit','Chrome／Edge 瀏覽紀錄',policy['browser_audit'],mapping(collectors.get('browser_history'))),('file_audit','文件操作稽核',policy['file_audit']['enabled'],mapping(collectors.get('directory_notifications')))]:
        if not online:state,reason='offline','端點離線'
        elif not received:state,reason='pending','端點尚未確認目前策略'
        elif report.get('status')=='failed':state,reason='failed','收集器失敗，請查看基本資訊'
        elif not desired:state,reason='disabled','有效策略已停收；歷史資料保留'
        elif key=='browser_audit' and report.get('status') in ('collecting','partial'):state,reason='reported',('部分瀏覽器設定檔待重試' if report['status']=='partial' else '端點回報可讀取瀏覽紀錄')
        elif key=='file_audit' and timestamp(report.get('active'))>0:state,reason='reported','端點回報目錄監看中；原生讀取另見端點明細（需元件 0.4.51）'
        else:state,reason='pending',str(report.get('status') or '尚未收到可用的收集器回報')[:120]
        add(key,name,desired,state,reason,report.get('checked_at'))
    from .file_access import options
    access=mapping(ext.get('document_native_read'));desired=options(policy['file_audit']['exclude_paths'])
    if not policy['file_audit']['enabled']:state,reason='disabled','一般檔案稽核停用'
    elif not online:state,reason='offline','端點離線'
    elif not fresh or access.get('filter_minimum_version')!='0.4.54':state,reason='pending','互動關聯、背景排除與開啟合併需原生元件 0.4.54；接收策略不代表已啟用'
    elif access.get('file_access_filter')!=desired:state,reason='pending','等待目前背景讀取排除設定的回報'
    elif access.get('status')=='interaction_context_unavailable':state,reason='pending','尚無可用使用者互動情境；普通開啟暫不列入，請查看端點診斷或切回完整程序存取'
    elif access.get('status') in ('collecting_native_reads','collecting_native_reads_limited','collecting_no_active_session','backlog_full'):state,reason='reported','元件已回報背景排除及開啟合併；互動關聯不代表已確認人工閱讀'
    else:state,reason='pending','等待文件收集器啟動或重試'
    add('file_access_filter','文件背景讀取排除',policy['file_audit']['enabled'],state,reason,ext.get('received'))
    add('allow_export','受控外發入口',policy['allow_export'],'reported' if received else 'pending',
        '設定供受控外發入口判斷；不代表其他檔案傳出管道已被阻擋' if received else '等待端點接收入口設定')
    add('upload_rules','上傳限制',policy['upload_rules'],'pending' if policy['upload_rules'] else 'disabled',
        '尚無此版 QoS／代理套用證據；請查看收集器診斷並實測' if policy['upload_rules'] else '未設定上傳速率規則')
    web=policy.get('website_control',{'enabled':False});report=mapping(ext.get('website_control'))
    from .serialization import canonical,digest
    if not online:state,reason='offline','端點離線，保留最後有效網站政策'
    elif not report.get('protocol'):state,reason='pending','原生元件尚不支援網站管制，請更新後確認'
    elif report.get('state') in ('failed','partial_or_failed'):state,reason='failed','網站政策衝突或套用失敗；請核對逐瀏覽器狀態'
    elif not fresh:state,reason='pending','原生元件回報已過期'
    elif not web['enabled'] and report.get('state')=='disabled':state,reason='disabled','網站管制停用'
    elif report.get('fingerprint')!=digest(canonical(web)):state,reason='pending','等待目前網站策略的元件回報'
    else:state,reason='reported','登錄已核對；瀏覽器政策與實際造訪仍待測試'
    if 'website_control' in sources:add('website_control','網站存取管制',web,state,reason,ext.get('received'))
    pubs=policy.get('application_publishers',[])
    if pubs and 'application_publishers' in sources:
        pub=mapping(ext.get('category_application_control'))
        ok=fresh and pub.get('fingerprint')==digest(canonical(pubs)) and pub.get('state')=='configured_requires_execution_test'
        add('application_publishers','分類發行者規則',pubs,'reported' if ok else 'pending','元件回報；仍需實際執行驗收' if ok else '等待支援分類規則的原生元件回報',ext.get('received'))
    return rows
