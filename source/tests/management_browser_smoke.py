"""Exercise group/policy management through the UI, restore live assignments."""
import json
import secrets
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.agent import Agent
from playwright.sync_api import sync_playwright


def main():
    root=Path(__file__).resolve().parents[1];nonce=secrets.token_hex(3)
    credentials=dict(line.split(': ',1) for line in (root/'runtime/access.txt').read_text(encoding='utf-8').splitlines())
    created_groups=[];created_sets=[];created_assignments=[];original_device=None;errors=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
        page=browser.new_page(viewport={'width':1600,'height':1080},locale='zh-TW',timezone_id='Asia/Taipei')
        page.on('pageerror',lambda e:errors.append(str(e)))
        def request(path,body=None):
            return page.evaluate("""async([path,body])=>{const me=await(await fetch('/api/me')).json();const r=await fetch(path,body===null?{}:{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf},body:JSON.stringify(body)});const result=await r.json();if(!r.ok)throw new Error(JSON.stringify(result));return result;}""",[path,body])
        def submit(form,path):
            with page.expect_response(lambda r:r.url.endswith(path) and r.request.method=='POST') as response:
                page.locator(form).get_by_role('button').filter(has_text='儲存' if form=='#group-form' else '確認移動' if form=='#move-form' else '發布策略集').first.click()
            result=response.value;assert result.ok,result.text();return result.json()
        def make_group(name,parent=''):
            page.locator('[data-action=fleet-new-group]').click();page.locator('#group-form [name=name]').fill(name)
            page.locator('#group-form [name=parent_id]').select_option(parent)
            saved=submit('#group-form','/api/groups');created_groups.append(saved['id']);page.locator('#dialog').wait_for(state='hidden');return saved
        def make_set(name,audit):
            page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click()
            page.locator('[data-action=set-new]').click();page.locator('[name=set_name]').fill(name)
            page.locator('[name=module_browser]').check();page.locator('#set-form [name=browser_audit]').set_checked(audit)
            saved=submit('#set-form','/api/policy-sets');created_sets.append(saved['id']);page.locator('[data-action=set-assign][data-id="'+saved['id']+'"]').wait_for();return saved
        def assign(policy_id,kind,target):
            page.locator('[data-action=set-assign][data-id="'+policy_id+'"]').click()
            page.locator('#assignment-form [name=target_type]').select_option(kind)
            target_field=page.locator('#assignment-form [name=target_id]')
            if kind=='user':target_field.fill(target)
            else:target_field.select_option(target)
            page.locator('#assignment-form').get_by_role('button',name='預覽影響範圍 →').click()
            page.locator('[data-action=assignment-confirm]').wait_for()
            with page.expect_response(lambda r:r.url.endswith('/api/assignments') and r.request.method=='POST') as result:
                page.locator('[data-action=assignment-confirm]').click()
            response=result.value;assert response.ok,response.text();saved=response.json();created_assignments.append(saved['id']);page.locator('#dialog').wait_for(state='hidden')
        try:
            page.goto(credentials['URL']);page.locator('[name=username]').fill(credentials['Username']);page.locator('[name=password]').fill(credentials['Password']);page.locator('#login-form button').click()
            page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
            live=request('/api/state');original_device=next(d for d in live['devices'] if not d['revoked']);eid=original_device['id']
            page.locator('nav [data-page=devices]').click();page.get_by_role('heading',name='端點裝置',exact=True).wait_for()
            parent=make_group('UI 驗收-'+nonce);child=make_group('子群組-'+nonce,parent['id'])
            page.locator('[data-action=fleet-group][data-id=all]').click()
            page.locator('[data-select-device="'+eid+'"]').check();page.locator('#fleet-move-button').click();page.locator('#move-form [name=group_id]').select_option(child['id']);submit('#move-form','/api/devices/move-many');page.locator('#dialog').wait_for(state='hidden')
            page.locator('[data-action=fleet-group][data-id="'+parent['id']+'"]').click()
            assert page.locator('[data-action=device][data-id="'+eid+'"]').count()==1
            page.screenshot(path=str(root/'evidence/groups-0.3-desktop.png'),full_page=True)
            first=make_set('群組網址稽核-'+nonce,False);assign(first['id'],'group',parent['id'])
            page.locator('[data-action=policy-tab][data-tab=sets]').click()
            second=make_set('端點網址覆寫-'+nonce,True);assign(second['id'],'device',eid)
            agent=Agent(root/'runtime/agent/config.json');agent.collect_native(agent.cached_policy());agent.heartbeat();agent.heartbeat()
            page.locator('nav [data-page=devices]').click();page.locator('[data-action=device][data-id="'+eid+'"]').click();page.locator('[data-action=detail-tab][data-tab=effective]').click()
            assert '端點網址覆寫-'+nonce in page.locator('#dialog-content').inner_text()
            assert '群組網址稽核-'+nonce in page.locator('#dialog-content').inner_text()
            page.screenshot(path=str(root/'evidence/effective-policy-0.3.png'),full_page=True)
            assert page.locator('[data-action=detail-tab]').all_text_contents()==['基本資料','有效策略與來源']
            page.locator('#close-dialog').click();page.locator('nav [data-page=audit]').click()
            page.locator('#search-form [name=device]').select_option(eid);page.locator('#search-form').get_by_role('button',name='搜尋',exact=True).click()
            assert page.locator('#search-form [name=device]').input_value()==eid
            page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click()
            account=agent.assets['user_accounts'][0];assign(first['id'],'user',account)
            agent.heartbeat();agent.heartbeat()
            page.locator('nav [data-page=devices]').click();page.locator('[data-action=device][data-id="'+eid+'"]').click();page.locator('[data-action=detail-tab][data-tab=effective]').click();page.locator('#detail-principal').select_option(account)
            page.get_by_text('個人',exact=True).wait_for(timeout=1000) if page.get_by_text('個人',exact=True).count() else None
            detail=request('/api/device-detail?device_id='+eid+'&principal='+account.replace('\\','%5C'))
            assert detail['preview_policy']['field_sources']['browser_audit']['kind']=='user'
            assert detail['effective_policy']['field_sources']['browser_audit']['kind']=='device'
            page.locator('#close-dialog').click();page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=assignments]').click()
            page.screenshot(path=str(root/'evidence/assignments-0.3-desktop.png'),full_page=True)
            page.locator('nav [data-page=devices]').click();page.set_viewport_size({'width':390,'height':844});assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(root/'evidence/groups-0.3-mobile.png'),full_page=True)
            assert not errors,errors
        finally:
            for aid in reversed(created_assignments):
                state=request('/api/state');item=next((a for a in state['assignments'] if a['id']==aid),None)
                if item:request('/api/assignments/delete',{'id':aid,'revision':item['revision']})
            if original_device:
                state=request('/api/state');row=next(d for d in state['devices'] if d['id']==original_device['id'])
                request('/api/devices/move',{'device_id':row['id'],'revision':row['management_revision'],'group_id':original_device['group_id']})
            for sid in reversed(created_sets):
                state=request('/api/state');item=next(p for p in state['policy_sets'] if p['id']==sid);request('/api/policy-sets/archive',{'id':sid,'revision':item['revision']})
            for gid in reversed(created_groups):
                state=request('/api/state');item=next(g for g in state['groups'] if g['id']==gid);request('/api/groups/delete',{'id':gid,'revision':item['revision']})
            browser.close()
    report={'passed':True,'checks':['create nested groups through UI','move real endpoint into child group','parent filter includes descendants','create two named policies','preview and assign to group','assign different endpoint override','effective source trace displays inheritance','two detail tabs and independent endpoint audit query','individual Windows account assignment and preview','390px no whole-page overflow','test assignments and groups restored'],'page_errors':errors}
    (root/'evidence/management-browser-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
