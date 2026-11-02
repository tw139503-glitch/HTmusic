/* HT Music: sèvè konplè (Node 18+). Pa gen depandans obligatwa; "nodemailer" sèlman pou imèl Gmail.
   Lanse:  node server.js        (gade README.md pou varyab yo)
   Fè 2FA admin:  node server.js --setup-2fa
   Sèvi: app la (/), admin (/admin), API a (/api/...), kòd konfimasyon (/api/verify/...) */
'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const E=process.env,PORT=+E.PORT||8787,ORIGIN=E.ALLOW_ORIGIN||'*',DEV=E.DEV_ECHO==='1',TRUST=E.TRUST_PROXY==='1';
const DATA=E.DATA_FILE||path.join(__dirname,'data.json'),WEB=E.WEB_DIR||(fs.existsSync(path.join(__dirname,'index.html'))?__dirname:path.join(__dirname,'..'));
const OWNER_KEY=E.ADMIN_KEY||'',STAFF_KEY=E.STAFF_KEY||'',TOTP=E.ADMIN_TOTP_SECRET||'';

/* ---------- 2FA (TOTP) ---------- */
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32dec(s){let bits='',out=[];for(const c of s.replace(/=+$/,'').toUpperCase()){const v=B32.indexOf(c);if(v<0)continue;bits+=v.toString(2).padStart(5,'0')}for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(out)}
function totp(secret,t){const c=Buffer.alloc(8);c.writeBigUInt64BE(BigInt(Math.floor(t/30000)));const h=crypto.createHmac('sha1',b32dec(secret)).update(c).digest(),o=h[19]&15;return String(((h.readUInt32BE(o)&0x7fffffff)%1e6)).padStart(6,'0')}
function totpOk(code){if(!TOTP)return true;const now=Date.now();for(const d of[-30000,0,30000])if(safeEq(totp(TOTP,now+d),String(code||'').trim()))return true;return false}
if(process.argv.includes('--setup-2fa')){const s=Array.from(crypto.randomBytes(20)).map(b=>B32[b%32]).join('');console.log('ADMIN_TOTP_SECRET='+s);console.log('otpauth://totp/HTMusic:admin?secret='+s+'&issuer=HTMusic');console.log('Mete secret la nan varyab ADMIN_TOTP_SECRET, epi ajoute l nan aplikasyon otantifikasyon ou.');process.exit(0)}
function safeEq(a,b){a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)}

/* ---------- done (fichye JSON) ---------- */
const DEFAULT={events:[],seq:1,users:{},tickets:[],takedown:[],
  cfg:{accts:[],plans:[],streamPay:{per:100,usd:5},maintenance:false,notice:'',appcfg:{gifts:[],promo:{on:false,title:'',text:''},texts:{}}},
  rates:{mode:'auto',manualHtg:0,buffer:3,market:{},effective:{},updated:0,source:'',spike:false,history:[]}};
let db=JSON.parse(JSON.stringify(DEFAULT));
try{const j=JSON.parse(fs.readFileSync(DATA,'utf8'));db=Object.assign(db,j);db.cfg=Object.assign({},DEFAULT.cfg,j.cfg||{});db.rates=Object.assign({},DEFAULT.rates,j.rates||{})}catch(e){}
let dirty=false,saving=false;
function save(){dirty=true}
setInterval(()=>{if(!dirty||saving)return;dirty=false;saving=true;const tmp=DATA+'.tmp';fs.writeFile(tmp,JSON.stringify(db),err=>{if(err){saving=false;dirty=true;return console.error('sove echwe',err.message)}fs.rename(tmp,DATA,e=>{saving=false;if(e)dirty=true})})},2000).unref();
function flushSync(){if(dirty){try{fs.writeFileSync(DATA,JSON.stringify(db))}catch(e){}}}
['SIGINT','SIGTERM'].forEach(s=>process.on(s,()=>{flushSync();process.exit(0)}));

/* ---------- zouti ---------- */
const MAXB=100*1024;
const clip=(s,n)=>String(s==null?'':s).slice(0,n);
const idOk=s=>/^[A-Za-z0-9_-]{4,64}$/.test(String(s||''));
function ipOf(req){return TRUST?String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress:req.socket.remoteAddress}
function hdr(extra){return Object.assign({'Access-Control-Allow-Origin':ORIGIN,'Access-Control-Allow-Headers':'Content-Type,Authorization','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'},extra||{})}
function send(res,code,obj){res.writeHead(code,hdr({'Content-Type':'application/json'}));res.end(JSON.stringify(obj))}
function readBody(req){return new Promise((ok,no)=>{let d='',n=0;req.on('data',c=>{n+=c.length;if(n>MAXB){if(n-c.length<=MAXB)no(Object.assign(new Error('twò gwo'),{code:413}));return}d+=c});req.on('end',()=>{try{ok(d?JSON.parse(d):{})}catch(e){no(Object.assign(new Error('JSON pa valab'),{code:400}))}});req.on('error',no)})}
const RL=new Map();
function limit(key,max,ms){const n=Date.now();let r=RL.get(key);if(!r||r.t<n){r={n:0,t:n+ms};RL.set(key,r)}return ++r.n<=max}
setInterval(()=>{const n=Date.now();for(const[k,v]of RL)if(v.t<n)RL.delete(k)},60e3).unref();

/* ---------- sesyon admin ---------- */
const SESS=new Map(),SESS_TTL=12*3600e3;
function who(req){const a=String(req.headers.authorization||'');if(!a.startsWith('Bearer '))return null;const s=SESS.get(a.slice(7));if(!s||s.exp<Date.now()){SESS.delete(a.slice(7));return null}return s}

/* ---------- itilizatè / evènman ---------- */
const TYPES=/^[a-z0-9_]{2,32}$/;
function upsert(ev,ip,ua){
  const uid=ev.uid;if(!idOk(uid))return;
  let u=db.users[uid];if(!u)u=db.users[uid]={uid,email:'',name:'',role:'',first:ev.at,last:ev.at,count:0,ip:'',ua:'',lang:'',blocked:false};
  u.last=ev.at;u.count++;u.ip=ip;u.ua=clip(ua,120);
  const d=ev.data||{};
  if(typeof d.email==='string'&&/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(d.email))u.email=clip(d.email.toLowerCase(),120);
  if(typeof d.name==='string'&&d.name)u.name=clip(d.name,60);
  if(typeof d.role==='string')u.role=clip(d.role,30);
  if(typeof d.lang==='string')u.lang=clip(d.lang,8);
}
function addEvents(list,ip,ua){
  const now=Date.now();let n=0;
  for(const x of list.slice(0,50)){
    if(!x||!TYPES.test(String(x.type||'')))continue;
    let data={};try{const s=JSON.stringify(x.data||{});if(s.length<=2000)data=JSON.parse(s)}catch(e){}
    const ev={id:db.seq++,at:now,type:x.type,uid:idOk(x.uid)?x.uid:'',sid:clip(x.sid,40),ip,ua:clip(ua,120),data};
    db.events.unshift(ev);upsert(ev,ip,ua);n++;
  }
  if(db.events.length>50000)db.events.length=50000;
  if(n)save();return n;
}
function isBlocked(uid,email){
  if(uid&&db.users[uid]&&db.users[uid].blocked)return true;
  if(email){const e=String(email).toLowerCase();return Object.values(db.users).some(u=>u.blocked&&u.email===e)}
  return false;
}

/* ---------- to chanj ---------- */
async function refreshRates(){
  try{
    const r=await fetch('https://open.er-api.com/v6/latest/USD'),j=await r.json();
    if(!j||!j.rates||!(j.rates.HTG>0))throw new Error('repons pa bon');
    const R=db.rates,prev=R.market&&R.market.HTG;
    if(prev&&Math.abs(j.rates.HTG-prev)/prev>0.02){R.spike=true;R.updated=Date.now();R.source='auto (varyasyon brid, kenbe ansyen an)';save();return}
    R.spike=false;R.market=j.rates;R.updated=Date.now();R.source='auto';recompute();
  }catch(e){console.error('to chanj echwe:',e.message)}
}
function recompute(){
  const R=db.rates,m=R.market||{};if(!m.HTG)return;
  const eff=Object.assign({},m);const base=R.mode==='manual'&&R.manualHtg>0?R.manualHtg:m.HTG-Math.max(0,+R.buffer||0);
  eff.HTG=Math.max(1,Math.round(base*100)/100);R.effective=eff;
  R.history.push({t:Date.now(),htg:eff.HTG,mode:R.mode});if(R.history.length>120)R.history.shift();save();
}
if(DEV!==true){refreshRates();setInterval(refreshRates,6*3600e3).unref()}

/* ---------- kòd konfimasyon (imèl / SMS) ---------- */
const VS=new Map(),VLAST=new Map();let mailer=null;
if(E.GMAIL_USER&&E.GMAIL_APP_PASSWORD){try{mailer=require('nodemailer').createTransport({service:'gmail',auth:{user:E.GMAIL_USER,pass:E.GMAIL_APP_PASSWORD}})}catch(e){console.error('nodemailer pa enstale: npm i nodemailer')}}
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const mask=(c,t)=>c==='email'?t.replace(/^(.).*(@.*)$/,'$1•••$2'):'••••'+t.replace(/\D/g,'').slice(-4);
async function deliver(channel,to,text,subject){
  if(DEV){console.log('[DEV]',to,'=>',text);return}
  if(channel==='email'){if(!mailer)throw new Error('imèl pa konfigire');await mailer.sendMail({from:'HT Music <'+E.GMAIL_USER+'>',to,subject:subject||'HT Music',text});return}
  const {TWILIO_SID:sid,TWILIO_TOKEN:tok,TWILIO_FROM:from}=E;if(!sid||!tok||!from)throw new Error('SMS pa konfigire');
  const r=await fetch('https://api.twilio.com/2010-04-01/Accounts/'+sid+'/Messages.json',{method:'POST',headers:{Authorization:'Basic '+Buffer.from(sid+':'+tok).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({To:to,From:from,Body:text})});
  if(!r.ok)throw new Error('SMS echwe');
}
setInterval(()=>{const n=Date.now();for(const[k,v]of VS)if(v.exp<n)VS.delete(k)},60e3).unref();

/* ---------- ticket ---------- */
const TTYPES=['asistans','siyale_mizik','siyale_albom','peman','kont'];
function pubTicket(t){return{id:t.id,type:t.type,status:t.status,created:t.created,updated:t.updated,reason:t.reason,ref:t.ref,msgs:t.msgs.map(m=>({from:m.from,at:m.at,text:m.text}))}}
const sanitizeRef=r=>r&&typeof r==='object'?{id:clip(r.id,64),title:clip(r.title,120)}:null;

/* ---------- konfig (validasyon) ---------- */
const METH=['bank','moncash','natcash','paypal','zelle','cashapp','venmo','wise'];
function cleanCfg(b,cur){
  const c=Object.assign({},cur);
  if(Array.isArray(b.accts))c.accts=b.accts.slice(0,12).map(a=>({method:METH.includes(a.method)?a.method:'bank',label:clip(a.label,60),acct:clip(a.acct,120),name:clip(a.name,80)})).filter(a=>a.label&&a.acct);
  if(Array.isArray(b.plans))c.plans=b.plans.slice(0,12).map(p=>{const o={};for(const k of Object.keys(p||{}).slice(0,20)){const v=p[k];o[clip(k,30)]=typeof v==='number'||typeof v==='boolean'?v:Array.isArray(v)?v.slice(0,12).map(x=>clip(x,100)):clip(v,200)}return o});
  if(b.streamPay&&typeof b.streamPay==='object'){const per=Math.round(+b.streamPay.per),usd=+b.streamPay.usd;if(per>=1&&per<=100000&&usd>=0&&usd<=1000)c.streamPay={per,usd}}
  if(typeof b.maintenance==='boolean')c.maintenance=b.maintenance;
  if(typeof b.notice==='string')c.notice=clip(b.notice,200);
  if(b.appcfg&&typeof b.appcfg==='object'){
    const a=b.appcfg,o={gifts:[],promo:{on:false,title:'',text:''},texts:{}};
    if(Array.isArray(a.gifts))o.gifts=a.gifts.slice(0,6).map(S=>({id:clip(S.id,30),name:clip(S.name,20),sym:clip(S.sym,2),tiers:(Array.isArray(S.tiers)?S.tiers:[]).slice(0,8).map(t=>[clip(t[0],30),clip(t[1],24),Math.round(Math.max(0,Math.min(1000,+t[2]||0))*100)/100,clip(t[3],4)]).filter(t=>t[1]&&t[2]>0)})).filter(S=>S.name&&S.tiers.length);
    if(a.promo&&typeof a.promo==='object')o.promo={on:!!a.promo.on,title:clip(a.promo.title,60),text:clip(a.promo.text,160)};
    if(a.texts&&typeof a.texts==='object')for(const k of Object.keys(a.texts).slice(0,60))o.texts[clip(k,200)]=clip(a.texts[k],300);
    c.appcfg=o;
  }
  return c;
}

/* ---------- rapò admin ---------- */
function summary(days){
  const now=Date.now(),since=now-days*864e5,by={},per={},pl={};let rev=0;
  for(let i=days-1;i>=0;i--)per[new Date(now-i*864e5).toISOString().slice(0,10)]={events:0,users:new Set()};
  for(const e of db.events){if(e.at<since)break;by[e.type]=(by[e.type]||0)+1;const k=new Date(e.at).toISOString().slice(0,10);if(per[k]){per[k].events++;if(e.uid)per[k].users.add(e.uid)}if(e.type==='play'&&e.data.title)pl[e.data.title]=(pl[e.data.title]||0)+1;if(e.type==='purchase'||e.type==='gift'||e.type==='subscribe')rev+=+e.data.amount||0}
  const us=Object.values(db.users),acc=us.filter(u=>u.email),byRole={};acc.forEach(u=>{const r=u.role||'konsomatè';byRole[r]=(byRole[r]||0)+1});
  const act=ms=>acc.filter(u=>u.last>=now-ms).length,on=us.filter(u=>u.last>=now-12e4);
  return{days,totalEvents:db.events.length,totalAccounts:acc.length,totalDevices:us.length,blocked:us.filter(u=>u.blocked).length,onlineAccounts:on.filter(u=>u.email).length,onlineAnon:on.filter(u=>!u.email).length,active24h:act(864e5),active7d:act(7*864e5),active30d:act(30*864e5),newAccounts7d:acc.filter(u=>u.first>=now-7*864e5).length,byRole,openTickets:db.tickets.filter(t=>t.status!=='fèmen').length,revenueHtg:rev,byType:by,series:Object.keys(per).map(d=>({day:d,events:per[d].events,users:per[d].users.size})),topTracks:Object.keys(pl).map(t=>({title:t,n:pl[t]})).sort((a,b)=>b.n-a.n).slice(0,8)};
}
const csvCell=v=>{let s=String(v==null?'':v);if(/^[=+\-@\t\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"'};

/* ---------- wout ---------- */
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript','.json':'application/json','.webmanifest':'application/manifest+json','.png':'image/png','.svg':'image/svg+xml'};
const STATIC={'/':'index.html','/index.html':'index.html','/admin':'admin.html','/admin.html':'admin.html','/manifest.webmanifest':'manifest.webmanifest','/sw.js':'sw.js','/icon-180.png':'icon-180.png','/icon-192.png':'icon-192.png','/icon-512.png':'icon-512.png'};
async function route(req,res){
  const u=new URL(req.url,'http://x'),p=u.pathname,ip=ipOf(req),ua=String(req.headers['user-agent']||'');
  if(req.method==='OPTIONS'){res.writeHead(204,hdr());return res.end()}
  if(req.method==='GET'&&STATIC[p]){
    const f=path.join(WEB,STATIC[p]);if(!fs.existsSync(f))return send(res,404,{error:'pa jwenn'});
    const ext=path.extname(f);res.writeHead(200,{'Content-Type':MIME[ext]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':ext==='.html'||p==='/sw.js'?'no-cache':'public, max-age=3600'});return fs.createReadStream(f).pipe(res);
  }
  if(p==='/health')return send(res,200,{ok:true});
  /* --- piblik --- */
  if(p==='/api/config'&&req.method==='GET'){const c=db.cfg;return send(res,200,{accts:c.accts,plans:c.plans,streamPay:c.streamPay,appcfg:c.appcfg})}
  if(p==='/api/rates'&&req.method==='GET'){const R=db.rates;if(!R.effective||!R.effective.HTG)return send(res,503,{error:'to poko disponib'});return send(res,200,{rates:R.effective,market:R.market,updated:R.updated})}
  if(req.method!=='POST'&&!p.startsWith('/api/admin/'))return send(res,404,{error:'pa jwenn'});
  if(p==='/api/log'){if(!limit('log:'+ip,600,6e4))return send(res,429,{error:'twòp demann'});const b=await readBody(req);return send(res,200,{ok:true,n:addEvents(Array.isArray(b.events)?b.events:[],ip,ua)})}
  if(p==='/api/status'){const b=await readBody(req);return send(res,200,{blocked:isBlocked(clip(b.uid,64),clip(b.email,120)),maintenance:!!db.cfg.maintenance,notice:db.cfg.notice||'',takedown:db.takedown})}
  if(p==='/api/ticket'){
    if(!limit('tk:'+ip,10,3600e3))return send(res,429,{error:'twòp demann'});
    const b=await readBody(req),msg=clip(b.message,1000).trim();
    if(!idOk(b.id)||!idOk(b.tok)||msg.length<5||!TTYPES.includes(b.type))return send(res,400,{error:'done pa valab'});
    if(db.tickets.some(t=>t.id===b.id))return send(res,409,{error:'deja egziste'});
    const now=Date.now();db.tickets.push({id:b.id,tok:sha(b.tok),type:b.type,status:'nouvo',created:now,updated:now,uid:idOk(b.uid)?b.uid:'',email:clip(b.email,120),reason:clip(b.reason,60),ref:sanitizeRef(b.ref),msgs:[{from:'user',at:now,text:msg}]});
    if(db.tickets.length>5000)db.tickets.shift();save();return send(res,200,{ok:true});
  }
  if(p==='/api/ticket/status'){
    const b=await readBody(req),items=(Array.isArray(b.items)?b.items:[]).slice(0,50),out=[];
    for(const it of items){const t=db.tickets.find(x=>x.id===it.id);if(t&&safeEq(t.tok,sha(String(it.tok||''))))out.push(pubTicket(t))}
    return send(res,200,{tickets:out});
  }
  if(p==='/api/ticket/reply'){
    if(!limit('tr:'+ip,30,3600e3))return send(res,429,{error:'twòp demann'});
    const b=await readBody(req),t=db.tickets.find(x=>x.id===b.id),tx=clip(b.text,1000).trim();
    if(!t||!safeEq(t.tok,sha(String(b.tok||''))))return send(res,404,{error:'pa jwenn'});
    if(tx.length<2)return send(res,400,{error:'mesaj twò kout'});
    if(t.msgs.length>=200)return send(res,400,{error:'twòp mesaj'});
    t.msgs.push({from:'user',at:Date.now(),text:tx});t.updated=Date.now();if(t.status==='fèmen'||t.status==='ouvè')t.status='nouvo';save();return send(res,200,{ok:true});
  }
  if(p==='/api/verify/send'){
    if(!limit('vs:'+ip,12,3600e3))return send(res,429,{error:'twòp demann'});
    const b=await readBody(req),channel=b.channel==='sms'?'sms':'email';
    let to=channel==='email'?String(b.email||'').trim().toLowerCase():String(b.phone||'').replace(/[\s().-]/g,'');
    if(channel==='email'&&!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to))return send(res,400,{error:'imèl pa valab'});
    if(channel==='sms'&&!/^\+[0-9]{8,15}$/.test(to))return send(res,400,{error:'telefòn dwe gen +kòd peyi'});
    const k=channel+':'+to;if((VLAST.get(k)||0)>Date.now()-45e3)return send(res,429,{error:'tann kèk segonn'});
    const code=String(crypto.randomInt(0,1e6)).padStart(6,'0'),salt=crypto.randomBytes(8).toString('hex'),id=crypto.randomBytes(12).toString('hex');
    await deliver(channel,to,'Kòd HT Music ou: '+code+' (valab 10 minit). Si se pa ou ki mande l, inyore mesaj sa a.','Kòd HT Music ou: '+code);
    VLAST.set(k,Date.now());VS.set(id,{h:sha(salt+code),salt,exp:Date.now()+600e3,n:0});
    return send(res,200,{id,channel,to:mask(channel,to)});
  }
  if(p==='/api/verify/check'){
    const b=await readBody(req),s=VS.get(String(b.id||''));if(!s||s.exp<Date.now())return send(res,400,{error:'kòd la ekspire'});
    if(++s.n>5){VS.delete(b.id);return send(res,429,{error:'twòp tantativ'})}
    if(!safeEq(sha(s.salt+String(b.code||'').replace(/\D/g,'')),s.h))return send(res,400,{error:'kòd la pa bon'});
    VS.delete(b.id);return send(res,200,{ok:true});
  }
  /* --- admin --- */
  if(p==='/api/admin/auth-info')return send(res,200,{twofa:!!TOTP,google:''});
  if(p==='/api/admin/login'){
    if(!limit('al:'+ip,6,15*60e3))return send(res,429,{error:'Twòp tantativ. Tann 15 minit.'});
    const b=await readBody(req),key=String(b.key||'');let role='';
    if(OWNER_KEY&&safeEq(key,OWNER_KEY))role='owner';else if(STAFF_KEY&&safeEq(key,STAFF_KEY))role='staff';
    if(!role||!totpOk(b.code))return send(res,401,{error:'Kle oswa kòd la pa bon'});
    const token=crypto.randomBytes(32).toString('hex');SESS.set(token,{role,who:role,exp:Date.now()+SESS_TTL});
    addEvents([{type:'admin_login',uid:'',data:{role}}],ip,ua);return send(res,200,{token,role});
  }
  if(p.startsWith('/api/admin/')){
    const s=who(req);if(!s)return send(res,401,{error:'Pa otorize'});
    const own=s.role==='owner';
    if(p==='/api/admin/logout'){for(const[k,v]of SESS)if(v===s)SESS.delete(k);return send(res,200,{ok:true})}
    if(p==='/api/admin/me')return send(res,200,{role:s.role,who:s.who,twofa:!!TOTP,recoveryLeft:0});
    if(p==='/api/admin/tickets'){const st=u.searchParams.get('status')||'';return send(res,200,{tickets:db.tickets.filter(t=>!st||t.status===st).sort((a,b)=>b.updated-a.updated).slice(0,500).map(t=>({id:t.id,type:t.type,status:t.status,created:t.created,updated:t.updated,uid:t.uid,email:t.email,reason:t.reason,ref:t.ref,msgs:t.msgs}))})}
    if(p==='/api/admin/ticket'&&req.method==='POST'){
      const b=await readBody(req),t=db.tickets.find(x=>x.id===b.id);if(!t)return send(res,404,{error:'pa jwenn'});
      const tx=clip(b.text,2000).trim();if(tx){t.msgs.push({from:'staff',at:Date.now(),text:tx,by:s.who});if(t.status==='nouvo')t.status='ouvè'}
      if(['nouvo','ouvè','fèmen'].includes(b.status))t.status=b.status;t.updated=Date.now();save();
      return send(res,200,{ok:true,ticket:{id:t.id,type:t.type,status:t.status,created:t.created,updated:t.updated,uid:t.uid,email:t.email,reason:t.reason,ref:t.ref,msgs:t.msgs}});
    }
    if(!own)return send(res,403,{error:'Sèlman mèt la ka fè sa'});
    if(p==='/api/admin/summary')return send(res,200,summary(Math.max(1,Math.min(90,+u.searchParams.get('days')||7))));
    if(p==='/api/admin/events'){
      const lim=Math.max(1,Math.min(200,+u.searchParams.get('limit')||50)),before=+u.searchParams.get('before')||Infinity,ty=u.searchParams.get('type')||'',ui=u.searchParams.get('uid')||'',tx=(u.searchParams.get('q')||'').toLowerCase(),out=[];
      for(const e of db.events){if(out.length>=lim)break;if(e.id>=before)continue;if(ty&&e.type!==ty)continue;if(ui&&e.uid!==ui)continue;if(tx&&JSON.stringify(e).toLowerCase().indexOf(tx)<0)continue;out.push(e)}
      return send(res,200,{events:out,next:out.length===lim?out[out.length-1].id:null});
    }
    if(p==='/api/admin/users')return send(res,200,{users:Object.values(db.users).sort((a,b)=>b.last-a.last).slice(0,5000)});
    if(p==='/api/admin/money'){
      const md=Math.max(1,Math.min(365,+u.searchParams.get('days')||30)),mt=(u.searchParams.get('q')||'').toLowerCase(),since=Date.now()-md*864e5;let inn=0,ou=0;const items=[];
      for(const e of db.events){if(e.at<since)break;const isIn=['purchase','gift','subscribe'].includes(e.type),isOut=e.type==='payout_request';if(!isIn&&!isOut)continue;if(mt&&JSON.stringify(e).toLowerCase().indexOf(mt)<0)continue;const a=+e.data.amount||0;isIn?inn+=a:ou+=a;items.push({id:e.id,at:e.at,dir:isIn?'in':'out',type:e.type,amount:a,uid:e.uid,data:e.data})}
      return send(res,200,{in:inn,out:ou,net:inn-ou,items:items.slice(0,300)});
    }
    if(p==='/api/admin/block'){const b=await readBody(req),x=db.users[b.uid];if(!x)return send(res,404,{error:'pa jwenn'});x.blocked=!!b.blocked;save();return send(res,200,{ok:true})}
    if(p==='/api/admin/takedown'){const b=await readBody(req),id=clip(b.id,64),i=db.takedown.indexOf(id);if(!id)return send(res,400,{error:'id manke'});if(b.remove&&i<0)db.takedown.push(id);if(!b.remove&&i>=0)db.takedown.splice(i,1);save();return send(res,200,{ok:true})}
    if(p==='/api/admin/config'){
      if(req.method==='POST'){const b=await readBody(req);db.cfg=cleanCfg(b,db.cfg);save();return send(res,200,{ok:true})}
      return send(res,200,db.cfg);
    }
    if(p==='/api/admin/rates'){
      if(req.method==='POST'){const b=await readBody(req),R=db.rates;if(b.mode==='auto'||b.mode==='manual')R.mode=b.mode;R.manualHtg=Math.max(0,Math.min(1000,+b.manualHtg||0));R.buffer=Math.max(0,Math.min(50,+b.buffer||0));recompute();return send(res,200,{ok:true})}
      const R=db.rates;return send(res,200,{state:{market:{HTG:R.market.HTG||0},effective:{HTG:R.effective.HTG||0},updated:R.updated,source:R.source,spike:R.spike,history:R.history},mode:R.mode,manualHtg:R.manualHtg,buffer:R.buffer});
    }
    if(p==='/api/admin/rates/refresh'){await refreshRates();return send(res,200,{ok:true})}
    if(p==='/api/admin/export.csv'){
      const rows=['id,date,type,uid,ip,data'];for(const e of db.events.slice(0,20000))rows.push([e.id,new Date(e.at).toISOString(),e.type,e.uid,e.ip,JSON.stringify(e.data)].map(csvCell).join(','));
      res.writeHead(200,hdr({'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="htmusic-istorik.csv"'}));return res.end(rows.join('\n'));
    }
  }
  send(res,404,{error:'pa jwenn'});
}
http.createServer((req,res)=>{route(req,res).catch(e=>{if(!res.headersSent)send(res,e.code===413?413:e.code===400?400:500,{error:e.code?e.message:'erè sèvè'});if(!e.code)console.error(e.message)})}).listen(PORT,()=>{
  console.log('HT Music sèvè ap koute sou pò',PORT,DEV?'(DEV_ECHO)':'');
  if(!OWNER_KEY)console.warn('ATANSYON: ADMIN_KEY pa defini. Admin lan pa ka konekte.');
});
