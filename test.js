import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
process.env.NODE_ENV='test';process.env.DATA_DIR=mkdtempSync(join(tmpdir(),'abhedit-'));
const {db,run,one,all,password,token,hash,verify}=await import('./db.js');
const {aggregate,cycle,deliver}=await import('./worker.js');
const {server}=await import('./server.js');
test.after(()=>{
 db.close();
 rmSync(process.env.DATA_DIR,{recursive:true});
});
test('Provider counts distinct affected accounts and DNS requires an exact proof',async()=>{
 assert.deepEqual([...aggregate({a:['A','A'],b:['A','B']})],[['A',2],['B',1]]);
 assert.equal(await verify({domain:'example.com',proof:'abcdef'},async()=>[['abc','def']]),true);
 assert.equal(await verify({domain:'example.com',proof:'abcdef'},async()=>[['abc']]),false);
});
test('Customer workflow and isolation',async(t)=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(r=>server.close(r)));
 const url='http://127.0.0.1:'+server.address().port;
 const post=(path,data,headers={})=>fetch(url+'/api/'+path,{method:'POST',headers:{Origin:'http://localhost:8080','Content-Type':'application/json',...headers},body:JSON.stringify(data)});
 const creds=password('example password');const keys={};
 for(const [name,id] of [['A',1],['B',2]]){keys[name]=token();run('insert into tenant values(?,?,?)',id,name,hash(keys[name]));run('insert into member(tenant,login,password,role) values(?,?,?,?)',id,name,creds,'admin')}
 run("insert into member(tenant,login,password,role) values(1,'reader',?,'viewer')",creds);
 async function login(name){const r=await post('login',{login:name,password:'example password'});assert.equal(r.status,200);return {Cookie:r.headers.get('set-cookie').split(';')[0]}}
 const a=await login('A'),b=await login('B'),reader=await login('reader');
 assert.equal((await post('assets',{domain:'example.com'},{...a,Origin:'https://other.example'})).status,403);
 assert.equal((await post('assets',{domain:'example.com'},a)).status,200);
 run("insert into entitlement values(1,'Pilot',1)");
 assert.equal((await post('assets',{domain:'extra.example.com'},a)).status,409);
 const evt={domain:'example.com',id:'record-1',title:'Synthetic exposure',severity:'High',count:3};
 const feed=k=>post('feed',evt,{Authorization:'Bearer '+keys[k]});
 assert.equal((await feed('A')).status,403);run('update asset set verified=?',Date.now());
 assert.equal((await feed('B')).status,403);assert.equal((await feed('A')).status,200);
 const change={id:1,status:'Resolved'};
 assert.equal((await post('status',change,b)).status,404);
 assert.equal((await post('status',change,reader)).status,403);
 assert.equal((await post('status',change,a)).status,200);assert.equal((await feed('A')).status,200);
 assert.equal(one('select status from finding').status,'Resolved');assert.equal(one('select count(*) n from outbox').n,1);
 const notePath='cases/1/notes';
 assert.equal((await post(notePath,{body:'Private case note'},b)).status,404);
 assert.equal((await post(notePath,{body:'View only'},reader)).status,403);
 assert.equal((await post(notePath,{body:'Reviewed with customer'},a)).status,200);
 assert.deepEqual((await (await fetch(url+'/api/'+notePath,{headers:reader})).json()).map(n=>n.body),['Reviewed with customer']);
 evt.category='Secret exposure';evt.channel='Paste site';assert.equal((await feed('A')).status,200);
 evt.channel='invalid';assert.equal((await feed('A')).status,400);
 const {checkClaims}=await import('./ransomware.js');
 const scan=()=>checkClaims({id:1,domain:'example.com'},'test',async url=>{
   assert.equal(url.searchParams.get('q'),'example.com');
   return Response.json({victims:[{website:'https://example.com',id:'abc',group:'Synthetic'},{website:'example.com.attacker.test',id:'wrong'}]});
 });
 await scan();await scan();
 assert.equal(one("select count(*) n from finding where source='Ransomware.live'").n,1);
 const workspace=await (await fetch(url+'/api/workspace',{headers:a})).json();
 assert.equal(workspace.findings[0].category,'Ransomware claim');assert.equal(workspace.coverage.length,2);
 assert.equal(workspace.findings[1].category,'Secret exposure');
 const report=await (await fetch(url+'/api/report',{headers:b})).json();assert.equal(report.findings.length,0);
 assert.equal((await post('logout',{},a)).status,200);
 assert.equal((await fetch(url+'/api/workspace',{headers:a})).status,401);
});

test('Scheduled DNS, provider coverage, and notification retries',async(t)=>{
 const config={HIBP_KEY:'test-breach-key',RANSOMWARE_LIVE_KEY:'test-claims-key',
  ALERT_ENDPOINTS:JSON.stringify({Scheduler:'https://receiver.example/intake'})};
 const previous=Object.fromEntries(Object.keys(config).map(key=>[key,process.env[key]]));
 Object.assign(process.env,config);
 t.after(()=>{
  for(const [key,value] of Object.entries(previous)){
   if(value===undefined)delete process.env[key];
   else process.env[key]=value;
  }
 });

 run('insert into tenant(id,name) values(3,?)','Scheduler');
 run('update asset set verified=0 where tenant<>3');
 const old=Date.now()-3600000;
 for(const domain of ['match.example','later.example','gone.example','timeout.example']){
  run('insert into asset(tenant,domain,proof,verified) values(3,?,?,?)',domain,'proof',old);
 }
 const options={
  resolveProof:asset=>verify(asset,async()=>{
   if(asset.domain==='gone.example')throw Object.assign(Error(),{code:'ENODATA'});
   if(asset.domain==='timeout.example')throw Object.assign(Error(),{code:'ETIMEOUT'});
   return [['proof']];
  }),
  pause:async()=>{}
 };
 const calls=[];
 await cycle({...options,request:async(url,opts)=>{
  const target=new URL(url);
  if(target.hostname==='api-pro.ransomware.live'){
   assert.equal(opts.headers['X-API-KEY'],'test-claims-key');
   calls.push('claims');
   return new Response('',{status:429});
  }
  assert.equal(target.hostname,'haveibeenpwned.com');
  assert.equal(opts.headers['hibp-api-key'],'test-breach-key');
  calls.push(target.pathname.split('/').at(-1));
  return target.pathname.endsWith('/match.example')?
   Response.json({synthetic:['Practice breach','Practice breach']}):
   new Response('',{status:404});
 }});
 assert.deepEqual(calls,['claims','match.example','later.example']);
 const assets=Object.fromEntries(all('select * from asset where tenant=3').map(asset=>[asset.domain,asset]));
 assert.equal(assets['gone.example'].verified,0);
 assert.equal(assets['timeout.example'].verified,old);
 assert.match(assets['timeout.example'].scan,/DNS lookup unavailable/);
 assert.ok(assets['match.example'].verified>old);
 const coverage=asset=>Object.fromEntries(all('select source,state from source_check where asset=?',asset.id)
  .map(check=>[check.source,check.state]));
 assert.deepEqual(coverage(assets['match.example']),{
  'Have I Been Pwned':'Scan completed','Ransomware.live':'Provider rate limited'
 });
 assert.deepEqual(coverage(assets['later.example']),{
  'Have I Been Pwned':'Scan completed','Ransomware.live':'Scan deferred after provider rate limit'
 });
 const finding=one('select id,count from finding where asset=?',assets['match.example'].id);
 assert.equal(finding.count,1);

 await cycle({...options,request:async url=>{
  if(new URL(url).hostname==='api-pro.ransomware.live')return Response.json({victims:[]});
  return new URL(url).pathname.endsWith('/match.example')?Response.json([]):new Response('',{status:404});
 }});
 assert.equal(coverage(assets['match.example'])['Have I Been Pwned'],'Scan failed; retry scheduled');
 assert.equal(coverage(assets['match.example'])['Ransomware.live'],'Scan completed');
 assert.ok(one('select id from finding where id=?',finding.id));

 const deliveries=[];
 const receiver=async(url,opts)=>{
  deliveries.push({url,key:opts.headers['Idempotency-Key'],event:JSON.parse(opts.body)});
  return deliveries.length===1?new Response('',{status:503}):new Response(null,{status:204});
 };
 await deliver(receiver);
 assert.ok(one('select due from outbox where finding=?',finding.id).due>Date.now());
 await deliver(receiver);
 assert.equal(deliveries.length,1);
 run('update outbox set due=0 where finding=?',finding.id);
 await deliver(receiver);
 assert.deepEqual(deliveries[1],deliveries[0]);
 assert.equal(deliveries[0].event.domain,'match.example');
 assert.equal(one('select * from outbox where finding=?',finding.id),undefined);
});
