import http from 'node:http';
import {readFileSync} from 'node:fs';
import {one,all,run,token,hash,matches,password,verify,domainName,record,checkSource,audit,transaction} from './db.js';
import {classify,guidance} from './intelligence.js';
const origin=new URL(process.env.PUBLIC_ORIGIN||'http://localhost:8080').origin;
const secure=origin.startsWith('https:')?'; Secure':'';
const files=new Map(['index.html','app.js','style.css'].map(n=>['/'+n,readFileSync(new URL('./public/'+n,import.meta.url))]));
const dummy=password(token()), attempts=new Map();
setInterval(()=>{for(const [key,v] of attempts)if(v.end<Date.now())attempts.delete(key);run('delete from session where expires<?',Date.now())},60000).unref();
function reject(status,message){throw Object.assign(Error(message),{status})}
async function input(req){let size=0;const chunks=[];for await(const c of req){size+=c.length;if(size>16384)reject(413,'Payload too large');chunks.push(c)}try{const v=JSON.parse(Buffer.concat(chunks));if(v&&typeof v==='object'&&!Array.isArray(v))return v}catch{}reject(400,'Expected JSON object')}
function limited(s,max){if(typeof s!=='string'||!s.trim()||s.length>max)reject(400,'Invalid field');return s.trim()}
export const server=http.createServer(async(req,res)=>{
 const path=req.url.split('?')[0],post=req.method==='POST';
 const json=(v)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(v))};
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
 try{
 if(req.method==='GET'&&(path==='/'||files.has(path))){const file=path==='/'?'/index.html':path;res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html; charset=utf-8');return res.end(files.get(file))}
 if(path==='/health'&&req.method==='GET')return json(one('select 1 as ready'));
 if(req.method!=='GET'&&!post)reject(405,'Method unsupported');
 if(post&&path==='/api/feed'){
 const key=(req.headers.authorization||'').match(/^Bearer ([a-f0-9]{64})$/)?.[1];const t=key&&one('select id from tenant where feed=?',hash(key));if(!t)reject(401,'Invalid feed token');
 const b=await input(req);const a=one('select id from asset where tenant=? and domain=? and verified>?',t.id,domainName(b.domain),Date.now()-86400000);
 if(!a)reject(403,'A current domain verification is required');
 if(!['High','Medium','Low'].includes(b.severity)||!Number.isSafeInteger(b.count)||b.count<1)reject(400,'Invalid severity or count');
 classify(b.category??'Unclassified exposure',b.channel??'Unspecified');
 transaction(()=>{
   record(a.id,'Licensed feed',limited(b.id,128),limited(b.title,160),b.severity,b.count,b.category,b.channel);
   checkSource(a.id,'Licensed feed','Event received');
 });return json({accepted:true});
 }
 if(post&&req.headers.origin!==origin)reject(403,'Origin mismatch');
 const sid=(req.headers.cookie||'').match(/(?:^|; )sid=([a-f0-9]{64})(?:;|$)/)?.[1];
 if(path==='/api/login'&&post){
 const b=await input(req),ip=req.socket.remoteAddress;let v=attempts.get(ip);if(!v||v.end<Date.now()){v={n:0,end:Date.now()+600000};attempts.set(ip,v)}if(v.n>=30)reject(429,'Try again later');
 const u=one('select * from member where login=?',limited(b.login,160));const ok=matches(limited(b.password,256),u?.password||dummy);
 if(!ok||!u?.password){v.n++;reject(401,'Invalid sign-in')}
 const s=token();run('insert into session values(?,?,?)',hash(s),u.id,Date.now()+8*3600000);res.setHeader('Set-Cookie','sid='+s+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+secure);return json({ok:true});
 }
 const u=sid&&one('select m.*,t.name from session s join member m on m.id=s.member join tenant t on t.id=m.tenant where s.token=? and s.expires>?',hash(sid),Date.now());if(!u)reject(401,'Sign in required');
 if(path==='/api/logout'&&post){run('delete from session where token=?',hash(sid));res.setHeader('Set-Cookie','sid=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict'+secure);return json({ok:true})}
 const findings=()=>all(`select f.id,a.domain,f.title,f.severity,f.count,f.status,f.source,f.seen,
 coalesce(i.category,case when f.source='Have I Been Pwned' then 'Identity exposure' else 'Unclassified exposure' end) category,
 coalesce(i.channel,case when f.source='Have I Been Pwned' then 'Breach database' else 'Unspecified' end) channel,
 coalesce(i.updated,f.seen) updated from finding f join asset a on a.id=f.asset left join intel i on i.finding=f.id
 where a.tenant=? order by (f.status='Resolved'),case f.severity when 'High' then 0 when 'Medium' then 1 else 2 end,f.id desc`,u.tenant);
 const noteRoute=path.match(/^\/api\/cases\/(\d+)\/notes$/);
 if(noteRoute){
   const id=Number(noteRoute[1]);
   if(!one('select f.id from finding f join asset a on a.id=f.asset where f.id=? and a.tenant=?',id,u.tenant))reject(404,'Unknown finding');
   if(post){
     if(u.role==='viewer')reject(403,'Analyst access required');
     const body=limited((await input(req)).body,2000);
     transaction(()=>{run('insert into case_note(finding,author,body) values(?,?,?)',id,u.login,body);audit(u.tenant,u.login,'Added note to case #'+id)});
   }
   return json(all('select author,body,created from case_note where finding=? order by id',id));
 }
 if(path==='/api/workspace'&&!post)return json({name:u.name,role:u.role,plan:one('select plan,domains from entitlement where tenant=?',u.tenant),guidance,coverage:all('select a.domain,c.source,c.state,c.checked from source_check c join asset a on a.id=c.asset where a.tenant=? order by c.checked desc,a.domain',u.tenant),assets:all('select * from asset where tenant=? order by domain',u.tenant),findings:findings(),history:all('select actor,event,at from audit where tenant=? order by id desc limit 100',u.tenant)});
 if(path==='/api/report'&&!post){res.setHeader('Content-Disposition','attachment; filename="exposure-report.json"');return json({workspace:u.name,generated:new Date().toISOString(),findings:findings()})}
 if(post&&path==='/api/status'){
 if(u.role==='viewer')reject(403,'Analyst access required');const b=await input(req);
 if(!['Open','Investigating','Resolved'].includes(b.status)||!Number.isSafeInteger(b.id))reject(400,'Invalid case update');
 transaction(()=>{const r=run('update finding set status=? where id=? and asset in(select id from asset where tenant=?)',b.status,b.id,u.tenant);if(!r.changes)reject(404,'Unknown finding');audit(u.tenant,u.login,'Case #'+b.id+' → '+b.status)});return json({ok:true});
 }
 if(post&&['/api/assets','/api/verify'].includes(path)){
 if(u.role!=='admin')reject(403,'Administrator access required');const b=await input(req);const d=domainName(b.domain);
 if(path==='/api/assets'){if(one('select id from asset where tenant=? and domain=?',u.tenant,d))reject(409,'Domain already registered');transaction(()=>{
 const plan=one('select domains from entitlement where tenant=?',u.tenant);
 if(plan&&one('select count(*) n from asset where tenant=?',u.tenant).n>=plan.domains)reject(409,'Workspace domain allowance reached');
 run('insert into asset(tenant,domain,proof) values(?,?,?)',u.tenant,d,'abhedit='+token());audit(u.tenant,u.login,'Added '+d)})}
 else{
 const a=one('select * from asset where tenant=? and domain=?',u.tenant,d);
 if(!a)reject(404,'Unknown domain');
 const ok=await verify(a).catch(()=>reject(503,'DNS lookup unavailable. Try again shortly.'));
 transaction(()=>{
   run('update asset set verified=?,scan=? where id=?',ok?Date.now():0,ok?'DNS verified':'DNS proof missing',a.id);
   if(ok)audit(u.tenant,u.login,'Verified '+d);
 });
 if(!ok)reject(422,'TXT verification did not succeed');
 }
 return json({ok:true});
 }
 reject(404,'Unknown endpoint');
 }catch(e){res.statusCode=e.status||(e.message==='Invalid domain'?400:500);json({error:res.statusCode===500?'Internal error':e.message})}
});
if(process.env.NODE_ENV!=='test')server.listen(Number(process.env.PORT||8080),process.env.BIND||'127.0.0.1');
