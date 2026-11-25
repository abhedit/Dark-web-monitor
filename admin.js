import {one,run,password,token,hash,transaction,audit} from './db.js';
import {readFileSync} from 'node:fs';
const [action,name,login,role='admin']=process.argv.slice(2);
if(!name||!['workspace','member','reset','feed-key','disable','plan'].includes(action))throw Error('Use workspace NAME, member NAME LOGIN ROLE, reset NAME LOGIN, disable NAME LOGIN feed-key NAME or plan NAME LABEL DOMAIN_LIMIT');
transaction(()=>{
 if(action==='workspace'){run('insert into tenant(name) values(?)',name);return}
 const t=one('select id from tenant where name=?',name);if(!t)throw Error('Unknown workspace');
 if(action==='plan'){
   const limit=Number(role);if(!login||!Number.isSafeInteger(limit)||limit<1)throw Error('Supply a plan label and positive domain limit');
   run('insert into entitlement values(?,?,?) on conflict(tenant) do update set plan=excluded.plan,domains=excluded.domains',t.id,login,limit);
 }else if(action==='feed-key'){const key=token();run('update tenant set feed=? where id=?',hash(key),t.id);console.log(key)}
 else if(action==='disable'||action==='reset'){
 const u=one('select id from member where tenant=? and login=?',t.id,login);if(!u)throw Error('Unknown member');
 run('delete from session where member=?',u.id);run('update member set password=? where id=?',action==='disable'?null:readPassword(),u.id);
 }else{if(!login||!['admin','analyst','viewer'].includes(role))throw Error('Expected login and admin, analyst or viewer');run('insert into member(tenant,login,password,role) values(?,?,?,?)',t.id,login,readPassword(),role)}
 audit(t.id,'Operator',action+' '+(login||''));
});
function readPassword(){const s=readFileSync(0,'utf8').trimEnd();if(s.length<12||s.length>256)throw Error('Supply a 12–256 character password on stdin');return password(s)}
