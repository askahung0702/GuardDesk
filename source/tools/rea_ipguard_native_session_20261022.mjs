// Private, static REA MCP session. Never launches or attaches to target code.
import {createRequire} from 'node:module';
import {mkdir, readdir, readFile, writeFile} from 'node:fs/promises';
import {resolve, join, relative, isAbsolute} from 'node:path';
const root=resolve(import.meta.dirname,'..');
const reaRoot='C:/Users/dev/workspace/HRM/tools/rea/node_modules/rea-agents';
const require=createRequire(join(reaRoot,'package.json'));
const {Client}=require('@modelcontextprotocol/client');
const {StdioClientTransport}=require('@modelcontextprotocol/client/stdio');
const seeded=process.argv.includes('--seeded');
const dir=join(root,seeded?'runtime/ipguard-rea-native-seeded-20261022':'runtime/ipguard-rea-native-20261022');
const inputs=join(dir,'requests');
await mkdir(inputs,{recursive:true});
const allowed=new Set(['binary_session','open_binary','analyze_function','search_strings','search_procedures','xrefs','trace_feature','procedure_callers','procedure_callees','inspect_analysis_view','close_binary']);
const stderr=await import('node:fs').then(fs=>fs.createWriteStream(join(dir,'server-stderr.log'),{flags:'a'}));
const transport=new StdioClientTransport({command:process.execPath,args:[join(reaRoot,'scripts/rea.mjs'),'mcp'],cwd:root,
 env:{...process.env,GHIDRA_INSTALL_DIR:join(root,'runtime/rea-native-tools/ghidra_12.1.4_PUBLIC'),
 JAVA_HOME:'C:/Program Files/OpenLogic/jdk-21.0.6.7-hotspot',GHIDRA_HEADLESS_MAXMEM:'2G',REA_GHIDRA_STARTUP_TIMEOUT_MS:'600000',
 ...(seeded?{REA_GHIDRA_SEED_FILE:join(root,'runtime/ipguard-native-hook-entry-seeds-20261022.tsv')}:{})},
 stderr:'pipe',maxBufferSize:32*1024*1024});
transport.stderr?.pipe(stderr);
const client=new Client({name:'guarddesk-private-static-review',version:'1.0.0'});
client.onerror=e=>console.log(JSON.stringify({client_error:String(e)}));
await client.connect(transport);
const catalog=await client.listTools();
await writeFile(join(dir,'tool-catalog.json'),JSON.stringify(catalog));
console.log(JSON.stringify({connected:true,tool_count:catalog.tools.length}));
const seen=new Set();let stop=false;
try{
 const end=Date.now()+45*60*1000;
 while(!stop&&Date.now()<end){
  const files=(await readdir(inputs)).filter(n=>/^\d{3}-[a-z0-9-]+\.json$/.test(n)).sort();
  for(const file of files){
   if(seen.has(file))continue;
   let request;try{request=JSON.parse(await readFile(join(inputs,file),'utf8'));}catch{continue;}
   if(request.name==='shutdown'){seen.add(file);stop=true;break;}
   if(!allowed.has(request.name))throw Error('Unapproved operation '+request.name);
   if(request.name==='open_binary'){
    const path=resolve(request.arguments.path);
    const rel=relative(join(root,'runtime/ipguard-installer-analysis-20261022'),path);
    if(rel.startsWith('..')||isAbsolute(rel))throw Error('Target outside analysis copies');
   }
   seen.add(file);const start=Date.now();
   console.log(JSON.stringify({started:file,operation:request.name}));
   try{
    const result=await client.callTool(request,{timeout:650000});
    await writeFile(join(dir,file),JSON.stringify(result));
    console.log(JSON.stringify({completed:file,seconds:(Date.now()-start)/1000,isError:result.isError===true,bytes:JSON.stringify(result).length}));
   }catch(error){
    await writeFile(join(dir,file),JSON.stringify({error:String(error)}));
    console.log(JSON.stringify({failed:file,error:String(error)}));
   }
  }
  if(!stop)await new Promise(r=>setTimeout(r,500));
 }
}finally{
 try{await client.callTool({name:'close_binary',arguments:{}},{timeout:60000});}catch{}
 await client.close();stderr.end();console.log(JSON.stringify({closed:true}));
}
