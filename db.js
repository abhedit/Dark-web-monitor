import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { resolveTxt } from 'node:dns/promises';
mkdirSync(process.env.DATA_DIR || 'data',{recursive:true,mode:0o700});
export const db = new DatabaseSync((process.env.DATA_DIR || 'data')+'/monitor.sqlite');
db.exec(`
PRAGMA busy_timeout=10000;
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS tenant(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL,feed TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS member(id INTEGER PRIMARY KEY,tenant INTEGER REFERENCES tenant,login TEXT UNIQUE,password TEXT,role TEXT);
CREATE TABLE IF NOT EXISTS session(token TEXT PRIMARY KEY,member INTEGER REFERENCES member,expires INTEGER);
CREATE TABLE IF NOT EXISTS asset(id INTEGER PRIMARY KEY,tenant INTEGER REFERENCES tenant,domain TEXT,proof TEXT,verified INTEGER DEFAULT 0,scan TEXT DEFAULT 'Awaiting first scan',checked TEXT,UNIQUE(tenant,domain));
CREATE TABLE IF NOT EXISTS finding(id INTEGER PRIMARY KEY,asset INTEGER REFERENCES asset,source TEXT,ref TEXT,title TEXT,severity TEXT,count INTEGER,status TEXT DEFAULT 'Open',seen TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(asset,source,ref));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,tenant INTEGER,actor TEXT,event TEXT,at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS outbox(finding INTEGER PRIMARY KEY REFERENCES finding, attempts INTEGER DEFAULT 0, due INTEGER DEFAULT 0);
CREATE TRIGGER IF NOT EXISTS finding_alert AFTER INSERT ON finding BEGIN INSERT INTO outbox(finding) VALUES(new.id); END;
CREATE TABLE IF NOT EXISTS entitlement(tenant INTEGER PRIMARY KEY REFERENCES tenant,plan TEXT,domains INTEGER CHECK(domains>0));
CREATE TABLE IF NOT EXISTS intel(finding INTEGER PRIMARY KEY REFERENCES finding,category TEXT,channel TEXT,updated TEXT);
CREATE TABLE IF NOT EXISTS case_note(id INTEGER PRIMARY KEY,finding INTEGER REFERENCES finding,author TEXT,body TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS notes_by_finding ON case_note(finding,id);
CREATE TABLE IF NOT EXISTS source_check(asset INTEGER REFERENCES asset,source TEXT,state TEXT,checked TEXT,PRIMARY KEY(asset,source));
CREATE INDEX IF NOT EXISTS audit_workspace ON audit(tenant,id);
`);
export const one=(sql,...p)=>db.prepare(sql).get(...p);
export const all=(sql,...p)=>db.prepare(sql).all(...p);
export const run=(sql,...p)=>db.prepare(sql).run(...p);
export const token=()=>randomBytes(32).toString('hex');
export const hash=s=>createHash('sha256').update(s).digest('hex');
export function password(s){const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(s,salt,64).toString('hex')}
export function matches(s,stored){const [salt,key]=stored.split(':');return timingSafeEqual(scryptSync(s,salt,64),Buffer.from(key,'hex'))}
export const audit=(t,a,e)=>run('insert into audit(tenant,actor,event) values(?,?,?)',t,a,e);
export function transaction(fn){db.exec('BEGIN IMMEDIATE');try{const result=fn();db.exec('COMMIT');return result}catch(e){db.exec('ROLLBACK');throw e}}
export function domainName(s){const d=String(s).trim().toLowerCase();if(d.length>253||! /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d))throw Error('Invalid domain');return d}
export async function verify(asset,resolver=resolveTxt){
 try{
  const records=await resolver('_abhedit-monitor.'+asset.domain);
  return records.some(record=>record.join('')===asset.proof);
 }catch(error){
  if(['ENODATA','ENOTFOUND'].includes(error.code))return false;
  throw error;
 }
}
export function record(asset,source,ref,title,severity,count,category,channel){
 const {id}=one(`insert into finding(asset,source,ref,title,severity,count) values(?,?,?,?,?,?)
 on conflict(asset,source,ref) do update set title=excluded.title,severity=excluded.severity,count=excluded.count
 returning id`,asset,source,ref,title,severity,count);
 run(`insert into intel values(?,?,?,CURRENT_TIMESTAMP) on conflict(finding) do update set
 category=coalesce(excluded.category,intel.category),channel=coalesce(excluded.channel,intel.channel),updated=CURRENT_TIMESTAMP`,id,category??null,channel??null);
}
export function checkSource(asset,source,state){
 run(`insert into source_check values(?,?,?,CURRENT_TIMESTAMP) on conflict(asset,source) do update set
 state=excluded.state,checked=excluded.checked`,asset,source,state);
}
