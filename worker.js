import {checkClaims} from './ransomware.js';
import {all,run,checkSource,verify,record,transaction} from './db.js';
import {setTimeout as delay} from 'node:timers/promises';
export function aggregate(payload){
 if(!payload||Array.isArray(payload)||typeof payload!=='object')throw Error('Invalid provider response');
 const counts=new Map();for(const names of Object.values(payload)){if(!Array.isArray(names)||names.some(n=>typeof n!=='string'||n.length>160))throw Error('Invalid provider response');for(const n of new Set(names))counts.set(n,(counts.get(n)||0)+1)}return counts;
}
export async function deliver(request=fetch){
 const endpoints=JSON.parse(process.env.ALERT_ENDPOINTS||'{}');
 for(const [workspace,url] of Object.entries(endpoints)){
 if(new URL(url).protocol!=='https:')throw Error('Alert destinations require HTTPS');
 const queue=all(`select o.finding,o.attempts,f.title,f.severity,f.count,a.domain from outbox o join finding f on f.id=o.finding join asset a on a.id=f.asset join tenant t on t.id=a.tenant where t.name=? and o.due<=? order by o.finding limit 50`,workspace,Date.now());
 for(const {attempts,...event} of queue){
 try{const res=await request(url,{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json','Idempotency-Key':'finding-'+event.finding},body:JSON.stringify(event)});if(!res.ok)throw Error();run('delete from outbox where finding=?',event.finding)}
 catch{run('update outbox set attempts=attempts+1,due=? where finding=?',Date.now()+Math.min(3600000,60000*2**Math.min(attempts,6)),event.finding)}
 }
 }
}
const HIBP='Have I Been Pwned';
const CLAIMS='Ransomware.live';

function failureState(error){
 if(error.message==='Provider HTTP 429')return 'Provider rate limited';
 if(/^Provider HTTP [0-9]+$/.test(error.message))return error.message;
 return 'Scan failed; retry scheduled';
}

async function checkBreaches(asset,key,request){
 const response=await request('https://haveibeenpwned.com/api/v3/breachedDomain/'+asset.domain,{
  headers:{'hibp-api-key':key,'user-agent':'ABHEDIT-Exposure-Monitor'},
  redirect:'error',
  signal:AbortSignal.timeout(30000)
 });
 if(!response.ok&&response.status!==404)throw Error('Provider HTTP '+response.status);
 const counts=response.status===404?new Map():aggregate(await response.json());
 transaction(()=>{
  for(const [name,count] of counts)record(asset.id,HIBP,name,name,'Medium',count,'Identity exposure','Breach database');
  checkSource(asset.id,HIBP,'Scan completed');
  run("update asset set checked=CURRENT_TIMESTAMP where id=?",asset.id);
 });
}

export async function cycle({resolveProof=verify,request=fetch,pause=delay}={}){
 const providers=[
  {source:CLAIMS,key:process.env.RANSOMWARE_LIVE_KEY,scan:checkClaims},
  {source:HIBP,key:process.env.HIBP_KEY,scan:checkBreaches}
 ].filter(provider=>provider.key);
 const rateLimited=new Set();

 for(const asset of all('select * from asset where verified>0 order by id')){
  let verified;
  try{
   verified=await resolveProof(asset);
  }catch{
   run("update asset set scan='DNS lookup unavailable; retry scheduled' where id=? and verified=?",asset.id,asset.verified);
   continue;
  }

  const result=run('update asset set verified=?,scan=? where id=? and verified=?',
   verified?Date.now():0,verified?'DNS verified':'DNS proof missing',asset.id,asset.verified);
  if(!verified||!result.changes)continue;

  for(const {source,key,scan} of providers){
   if(rateLimited.has(source)){
    checkSource(asset.id,source,'Scan deferred after provider rate limit');
    continue;
   }
   try{
    await scan(asset,key,request);
   }catch(error){
    checkSource(asset.id,source,failureState(error));
    if(error.message==='Provider HTTP 429')rateLimited.add(source);
   }
   if(source===HIBP&&!rateLimited.has(source))await pause(2000);
  }
 }
}
if(process.env.NODE_ENV!=='test'){
 let nextScan=0;
 do{
 if(Date.now()>=nextScan){await cycle();nextScan=Date.now()+12*3600000}
 await deliver();if(process.argv.includes('--once'))break;await delay(60000);
 }while(true)
}
