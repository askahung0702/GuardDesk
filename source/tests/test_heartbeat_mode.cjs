// Exercise the shipped detail renderer and click handler without a center or listener.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

async function run() {
  const clicks = [];
  const writes = [];
  const device = {id:'test-pc',name:'TEST',availability:'offline',offline_days:3,
    last_offline_seconds:4800,heartbeat_only:0,mode_ack:0,mode_revision:0,inventory:{}};
  let html = '';
  const ctx = vm.createContext({
    document:{addEventListener:(type,fn)=>{if(type==='click')clicks.push(fn);}},
    user:{role:'admin'}, kinds:{}, esc:String, relative:()=> '3 天前', date:String,
    dialog:(_,body)=>{html=body;}, $:()=>null, refresh:async()=>{}, toast:()=>{},
    api:async(url,body)=>{
      if(body){
        assert.equal(url,'/api/devices/heartbeat-mode');
        assert.equal(body.device_id,device.id);
        assert.equal(body.revision,device.mode_revision);
        writes.push(body.enabled);
        device.heartbeat_only=Number(body.enabled);
        device.mode_revision++;
      }
      return {device:{...device},effective_policy:{group_path:[]}};
    }
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../guarddesk/static/management.js'),'utf8'),ctx);
  vm.runInContext("detailBasic=()=>''",ctx);
  await ctx.loadDetail(device.id);
  const actions = () => [...html.matchAll(/data-action="([^"]+)"/g)].map(match=>match[1]).filter(key=>key!=='detail-tab');
  assert.deepEqual(actions(),['detail-move','detail-assign','detail-heartbeat-mode','purge-retire']);
  assert.match(html,/連續離線 3 天/);
  assert.match(html,/上次離線 未滿 1 天/);
  const click = async () => {
    const button={dataset:{action:'detail-heartbeat-mode',id:device.id},disabled:false};
    for(const listener of clicks)
      await listener({target:{closest:selector=>selector==='[data-action]'?button:null}});
  };
  await click();
  assert.deepEqual(writes,[true]);
  assert.match(html,/>恢復正常</);
  assert.match(html,/等待端點管理員元件回報解除管控/);
  device.mode_ack=device.mode_revision;
  await ctx.loadDetail(device.id);
  assert.match(html,/已回報解除 GuardDesk 管控/);
  await click();
  assert.deepEqual(writes,[true,false]);
  assert.match(html,/等待端點管理員元件接收策略/);
  assert.match(html,/>只回報心跳</);
  ctx.user.role='auditor';
  await ctx.loadDetail(device.id);
  assert.deepEqual(actions(),[]);
}
run().catch(error=>{console.error(error);process.exitCode=1;});
