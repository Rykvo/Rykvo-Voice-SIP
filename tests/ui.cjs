const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('app/web/index.html', 'utf8');
class Node {
  constructor() { this.value=''; this.hidden=false; this.children=[]; this.dataset={}; this.attributes={}; this.classList={toggle(){}}; this.replacements=0; this.listeners={}; }
  append(...items) { this.children.push(...items); }
  replaceChildren(fragment) { this.children=fragment.children || []; this.replacements++; }
  setAttribute(key,value) { this.attributes[key]=value; }
  addEventListener(type, callback) { (this.listeners[type] ||= []).push(callback); }
  getAttribute(key) { return this.attributes[key]; }
  removeAttribute(key) { delete this.attributes[key]; }
  focus() { this.focused=true; }
  close(value='') { this.returnValue=value; for (const callback of this.listeners.close || []) callback(); }
  reset() {}
  showModal() {}
}
const nodes=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match=>[match[1],new Node()]));
const context={
  document:{getElementById:id=>{assert.ok(nodes[id],id);return nodes[id]},createElement:()=>new Node(),createDocumentFragment:()=>new Node(),querySelectorAll:()=>[]},
  fetch:()=>new Promise(()=>{}),setTimeout:()=>0,clearTimeout(){},setInterval:()=>0,
  navigator:{clipboard:{async writeText(value){context.copied=value}}},
  AbortController,Date,console
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('app/web/app.js','utf8')+'\nthis.test={render,selectFilter,renderClients,statusOf,showLogin,showHelp,copyField,confirmAction,validateForm,removeClient};',context);
const clients=[
 {id:1,name:'one',ip:'10.77.0.2',start:20000,end:29999,exists:true,enabled:true,lastHandshake:new Date().toISOString()},
 {id:2,name:'two',ip:'10.77.0.3',start:30000,end:39999,exists:true,enabled:true,lastHandshake:null},
 {id:3,name:'three',ip:'10.77.0.4',start:40000,end:49999,exists:true,enabled:false,lastHandshake:null}
];
context.test.render({clients,csrf:'test',publicIp:'127.0.0.1',sipHost:'127.0.0.1',settings:{sipDomain:'',panelDomain:''}});
assert.equal(nodes['stat-all'].textContent,3);
assert.equal(nodes['stat-online'].textContent,1);
assert.equal(nodes['stat-offline'].textContent,2);
assert.equal(nodes.clients.children.length,3);
const before=nodes.clients.replacements;
context.test.renderClients();
assert.equal(nodes.clients.replacements,before,'Unchanged rows should not redraw');
context.test.selectFilter('online');assert.equal(nodes.clients.children.length,1);
context.test.selectFilter('offline');assert.equal(nodes.clients.children.length,2);
nodes.search.value='two';context.test.renderClients();assert.equal(nodes.clients.children.length,1);
nodes.search.value='missing';context.test.renderClients();assert.equal(nodes.clients.children.length,0);
assert.equal(nodes.empty.hidden,false);
console.log('PASS: three counters, connected/disconnected filters, search, unchanged rows retained.');

nodes.username.value='admin';context.test.showLogin();assert.equal(nodes.username.value,'');
assert.ok(!/<input[^>]+id="username"[^>]+value=/.test(html));
console.log('PASS: login account is blank by default and after logout.');

context.test.render({clients,csrf:'test',publicIp:'127.0.0.1',sipHost:'sip.example.com',settings:{sipDomain:'sip.example.com',panelDomain:'panel.example.com'}});
context.test.showHelp(clients[0]);
assert.ok(!nodes['connect-sip'] && !nodes['copy-sip']);
assert.equal(nodes['connect-endpoint'].value,'https://sip.example.com/api/connect');
context.test.copyField('connect-endpoint').then(() => {
 assert.equal(context.copied,'https://sip.example.com/api/connect');
 context.test.render({clients,csrf:'test',publicIp:'127.0.0.1',sipHost:'127.0.0.1',settings:{sipDomain:'',panelDomain:''}});
 context.test.showHelp(clients[0]);
 assert.equal(nodes['connect-endpoint'].value,'https://127.0.0.1/api/connect');
 console.log('PASS: Single enrollment address uses SIP domain, clipboard copy, and IP fallback.');
}).catch(error => {console.error(error);process.exitCode=1});


assert.ok(!/\b(?:alert|confirm|prompt|reportValidity)\s*\(/.test(fs.readFileSync('app/web/app.js','utf8')));
for (const form of html.matchAll(/<form\b[^>]*>/g)) assert.ok(form[0].includes('novalidate'));
assert.ok(html.includes('role="alertdialog"'));
const invalid = new Node();
invalid.willValidate=true;invalid.validity={valid:false,valueMissing:true};invalid.attributes['aria-label']='账号';
assert.equal(context.test.validateForm({elements:[invalid]},'login-error'),false);
assert.equal(nodes['login-error'].textContent,'请填写账号');
assert.equal(invalid.focused,true);
invalid.validity={valid:true};
assert.equal(context.test.validateForm({elements:[invalid]},'login-error'),true);
console.log('PASS: all forms use inline validation; no browser alert, confirm or prompt.');

(async () => {
 const calls=[];
 context.fetch=async (path,options) => {
  calls.push([path,options.method]);
  return {ok:true,json:async () => options.method==='DELETE' ? {} : {clients,csrf:'test',publicIp:'127.0.0.1',settings:{sipDomain:'',panelDomain:''}}};
 };
 const button=new Node();
 let task=context.test.removeClient(clients[0],button);
 assert.equal(calls.length,0,'No delete before confirmation');
 assert.equal(nodes['confirm-cancel'].focused,true);
 nodes['confirm-dialog'].close();
 await task;
 assert.equal(calls.length,0,'Cancel and Escape must not delete');
 assert.equal(button.disabled,false);
 task=context.test.removeClient(clients[0],button);
 assert.equal(calls.length,0);
 nodes['confirm-dialog'].close('confirm');
 // The initial page load is pending in the fixture; skip its shared refresh task.
 vm.runInContext('refreshTask = null',context);
 await task;
 assert.deepEqual(calls[0],['/api/clients/1','DELETE']);
 assert.equal(calls.filter(call=>call[1]==='DELETE').length,1);
 assert.equal(button.disabled,false);
 console.log('PASS: in-page confirmation cancels safely and sends one delete after approval.');
})().catch(error=>{console.error(error);process.exitCode=1});
