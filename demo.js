// Run against a separate, disposable database for sales demonstrations.
import {resolve} from 'node:path';
import {existsSync} from 'node:fs';
const dir=resolve(process.env.DEMO_DIR||'demo-data');
if(existsSync(resolve(dir,'monitor.sqlite')))throw Error('Choose an empty DEMO_DIR for a new demonstration');
process.env.DATA_DIR=dir;
const {run,record,transaction,token,password}=await import('./db.js');
const secret=token().slice(0,24);
transaction(()=>{
 run("insert into tenant(id,name) values(1,'Northwind · Synthetic demo')");
 run("insert into member(tenant,login,password,role) values(1,'demo',?,'admin')",password(secret));
 run("insert into entitlement values(1,'Customer pilot',5)");
 run("insert into asset(id,tenant,domain,proof,scan) values(1,1,'northwind.example',?,'Synthetic demonstration')",'abhedit='+token());
 const cases=[
 ['Session exposure','Messaging channel','Session exposure reported','High'],
 ['Secret exposure','Paste site','Integration key exposure reported','High'],
 ['Brand mention','Forum','Company name mentioned in a forum','Low']
 ];
 for(const [category,channel,title,severity] of cases)record(1,'Synthetic demo',category,title,severity,1,category,channel);
});
console.log('Demo directory:',dir,'\nUsername: demo\nTemporary password:',secret);
