import {createHash} from 'node:crypto';
import {record,transaction,checkSource} from './db.js';

function exactDomain(raw,domain){
  if(typeof raw!=='string'||!raw.trim())return false;
  try{
    const parsed=new URL(raw.includes('://')?raw:'https://'+raw);
    return ['https:','http:'].includes(parsed.protocol)&&parsed.hostname.toLowerCase()===domain;
  }catch{return false}
}
export async function checkClaims(asset,key,request=fetch){
  const url=new URL('https://api-pro.ransomware.live/victims/search');
  url.searchParams.set('q',asset.domain);
  const res=await request(url,{headers:{'X-API-KEY':key},redirect:'error',signal:AbortSignal.timeout(30000)});
  if(!res.ok)throw Error('Provider HTTP '+res.status);
  const payload=await res.json();
  const rows=Array.isArray(payload)?payload:payload?.victims;
  if(!Array.isArray(rows))throw Error('Invalid provider response');
  transaction(()=>{
    for(const item of rows){
      if(!exactDomain(item?.website??item?.domain,asset.domain))continue;
      const group=String(item.group_name||item.group||'Unattributed').slice(0,80);
      const ref=String(item.id||createHash('sha256').update(JSON.stringify([asset.domain,group,item.published||item.attackdate||item.post_title])).digest('hex'));
      record(asset.id,'Ransomware.live',ref,'Reported ransomware claim · '+group,'High',1,'Ransomware claim','Leak site');
    }
    checkSource(asset.id,'Ransomware.live','Scan completed');
  });
}
