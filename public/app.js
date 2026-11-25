const $=id=>document.getElementById(id);
let state,tab='Findings';
function el(tag,value){const n=document.createElement(tag);if(value!==undefined)n.textContent=value;return n}
async function api(path,body){const r=await fetch('/api/'+path,body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});const data=await r.json();if(!r.ok){if(r.status===401)showLogin();throw Error(data.error)}return data}
function showLogin(){$('login').hidden=false;$('desk').hidden=true;$('logout').hidden=true;state=null}
async function action(fn){$('message').textContent='';try{await fn()}catch(e){$('message').textContent=e.message}}
async function load(){state=await api('workspace');$('login').hidden=true;$('desk').hidden=false;$('logout').hidden=false;render()}
$('signin').onsubmit=e=>{e.preventDefault();action(async()=>{await api('login',Object.fromEntries(new FormData(e.target)));e.target.reset();await load()})};
$('logout').onclick=()=>action(async()=>{await api('logout',{});showLogin()});
$('refresh').onclick=()=>action(load);
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{tab=b.dataset.tab;render()});
function render(){
 $('workspace').textContent=state.name+' / '+state.role;
 const metrics=$('metrics');metrics.replaceChildren();
 for(const [v,label] of [[state.findings.filter(f=>f.status!=='Resolved').length,'Active cases'],[state.findings.filter(f=>f.severity==='High'&&f.status!=='Resolved').length,'High priority'],[state.assets.filter(a=>a.verified>Date.now()-86400000).length,'Verified domains']]){const box=el('div');box.append(el('strong',v),el('span',label));metrics.append(box)}
 document.querySelectorAll('[data-tab]').forEach(b=>b.setAttribute('aria-pressed',b.dataset.tab===tab));
 const c=$('content');c.replaceChildren(el('h2',tab));
 function row(){const r=el('div');r.className='row';c.append(r);return r}
 if(tab==='Findings'){
 const q=el('input');q.type='search';q.placeholder='Search cases, domains and sources';q.setAttribute('aria-label',q.placeholder);c.append(q);
 function list(){c.querySelectorAll('.row').forEach(n=>n.remove());const found=state.findings.filter(f=>[f.title,f.domain,f.status,f.severity,f.channel,f.category,f.source].join(' ').toLowerCase().includes(q.value.toLowerCase()));
 if(!found.length)row().append(el('p',state.findings.length?'No matching findings.':'No findings received. Verify a domain and connect a feed to begin.'));
 for(const f of found){const r=row();r.append(el('strong',f.title),el('span',f.domain+' · '+f.severity+' priority · '+f.count+' affected'),el('small',f.source+' · First seen '+f.seen+' UTC'));
 r.append(el('span',f.category+' · '+f.channel));
 const details=el('details');details.append(el('summary','Investigation'));
 details.ontoggle=()=>{if(details.open&&!details.dataset.loaded)action(async()=>{
   const notes=await api('cases/'+f.id+'/notes');if(details.dataset.loaded)return;details.dataset.loaded='true';
   details.append(el('p',state.guidance[f.category]),el('small','Last ingested '+f.updated+' UTC'));
   const history=el('div');details.append(history);
   function display(entries){history.replaceChildren();for(const n of entries)history.append(el('p',n.body),el('small',n.author+' · '+n.created+' UTC'))}
   display(notes);
   if(state.role!=='viewer'){
     const form=el('form'),label=el('label','Investigation note'),field=el('textarea');
     field.required=true;field.maxLength=2000;label.append(field);form.append(label,el('button','Save note'));details.append(form);
     form.onsubmit=e=>{e.preventDefault();action(async()=>{display(await api('cases/'+f.id+'/notes',{body:field.value}));field.value=''})};
   }
 })};r.append(details);
 if(state.role==='viewer')r.append(el('span',f.status));else{const s=el('select');s.setAttribute('aria-label','Status for '+f.title);for(const v of ['Open','Investigating','Resolved'])s.append(new Option(v,v));s.value=f.status;s.onchange=()=>action(async()=>{try{await api('status',{id:f.id,status:s.value})}finally{await load()}});r.append(s)}}}
 q.oninput=list;list();
 }else if(tab==='Coverage'){
 if(!state.coverage.length)row().append(el('p','No source activity recorded. Verify a customer domain and configure an intelligence provider.'));
 for(const check of state.coverage)row().append(el('strong',check.source),el('p',check.domain+' · '+check.state),el('small','Recorded '+check.checked+' UTC'));
 }else if(tab==='Domains'){
 if(state.plan)c.append(el('p',state.plan.plan+' · '+state.assets.length+' of '+state.plan.domains+' domain slots used'));
 if(state.role==='admin'){const form=el('form'),label=el('label','Customer domain'),input=el('input');input.required=true;input.placeholder='example.com';label.append(input);form.append(label,el('button','Add domain'));form.onsubmit=e=>{e.preventDefault();action(async()=>{await api('assets',{domain:input.value});await load()})};c.append(form)}
 if(!state.assets.length)row().append(el('p','No domains registered.'));
 for(const a of state.assets){const r=row();r.append(el('strong',a.domain),el('p',a.verified>Date.now()-86400000?'Verified':'Verification required'),el('small',a.scan+(a.checked?' · Last successful HIBP scan '+a.checked+' UTC':'')));
 if(state.role==='admin'){r.append(el('code','TXT _abhedit-monitor.'+a.domain+'  '+a.proof));const b=el('button','Check DNS');b.onclick=()=>action(async()=>{await api('verify',{domain:a.domain});await load()});r.append(b)}}
 }else{if(!state.history.length)row().append(el('p','No activity recorded.'));for(const h of state.history)row().append(el('strong',h.event),el('small',h.actor+' · '+h.at+' UTC'))}
}
load().catch(e=>{showLogin();if(e.message!=='Sign in required')$('message').textContent=e.message});
