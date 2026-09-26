const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('app/web/index.html', 'utf8');
const script = fs.readFileSync('app/web/app.js', 'utf8');
class Node {
  constructor() { this.value=''; this.hidden=false; this.children=[]; this.dataset={}; this.attributes={}; this.classList={toggle(){}}; this.replacements=0; this.listeners={}; }
  append(...items) { this.children.push(...items); }
  replaceChildren(fragment) { this.children=fragment.children || []; this.replacements++; }
  setAttribute(key,value) { this.attributes[key]=value; }
  addEventListener(type,callback) { (this.listeners[type] ||= []).push(callback); }
  getAttribute(key) { return this.attributes[key]; }
  removeAttribute(key) { delete this.attributes[key]; }
  focus() { this.focused=true; }
  close(value='') { this.open=false; this.returnValue=value; for (const callback of this.listeners.close || []) callback(); }
  reset() {}
  showModal() { this.open=true; }
}
function createUI() {
  const nodes=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match=>[match[1],new Node()]));
  const context={
    document:{getElementById:id=>{assert.ok(nodes[id],id);return nodes[id]},createElement:()=>new Node(),createDocumentFragment:()=>new Node(),querySelectorAll:selector=>selector==='dialog[open]' ? Object.values(nodes).filter(node=>node.open) : []},
    fetch:()=>new Promise(()=>{}),setTimeout:()=>0,clearTimeout(){},setInterval:()=>0,
    navigator:{clipboard:{async writeText(value){context.copied=value}}},AbortController,Date,console
  };
  vm.createContext(context);
  vm.runInContext(script+'\nthis.test={render,selectFilter,renderClients,showLogin,showHelp,generateToken,copyField,validateForm,removeClient};',context);
  return {context,nodes,test:context.test};
}
const clients=[
  {id:1,name:'one',ip:'10.77.0.2',start:20000,end:29999,exists:true,enabled:true,lastHandshake:new Date().toISOString()},
  {id:2,name:'two',ip:'10.77.0.3',start:30000,end:39999,exists:true,enabled:true,lastHandshake:null},
  {id:3,name:'three',ip:'10.77.0.4',start:40000,end:49999,exists:true,enabled:false,lastHandshake:null}
];
const state={clients,csrf:'test',publicIp:'127.0.0.1',administrator:{username:'admin'},settings:{sipDomain:'sip.example.com',panelDomain:'panel.example.com'}};
const calls=[];
const codes=new Map();
let generation=0;
const response=data=>({ok:true,json:async()=>data});
async function backend(path,options) {
  calls.push([path,options.method]);
  const match=path.match(/^\/api\/clients\/(\d+)\/enrollment$/);
  if (match) {
    const id=Number(match[1]);
    if (options.method==='POST') codes.set(id,{token:String(++generation).repeat(43),hasCode:true});
    return response({endpoint:`https://${state.settings.sipDomain || state.publicIp}/api/connect`,...(codes.get(id) || {token:null,hasCode:false})});
  }
  return response(options.method==='DELETE' ? {} : state);
}
async function main() {
  const {context,nodes,test}=createUI();
  context.fetch=backend;
  test.render(state);
  assert.equal(nodes['stat-all'].textContent,3);
  assert.equal(nodes['stat-online'].textContent,1);
  assert.equal(nodes['stat-offline'].textContent,2);
  assert.equal(nodes.clients.children.length,3);
  const before=nodes.clients.replacements;
  test.renderClients();assert.equal(nodes.clients.replacements,before);
  test.selectFilter('online');assert.equal(nodes.clients.children.length,1);
  test.selectFilter('offline');assert.equal(nodes.clients.children.length,2);
  nodes.search.value='two';test.renderClients();assert.equal(nodes.clients.children.length,1);
  nodes.search.value='missing';test.renderClients();assert.equal(nodes.clients.children.length,0);
  assert.equal(nodes.empty.hidden,false);
  console.log('PASS: counters, filters, search and unchanged rows.');

  nodes.username.value='admin';test.showLogin();assert.equal(nodes.username.value,'');
  assert.ok(!/<input[^>]+id="username"[^>]+value=/.test(html));
  assert.ok(!/\b(?:alert|confirm|prompt|reportValidity)\s*\(/.test(script));
  assert.ok(!/localStorage|sessionStorage/.test(script));
  for (const form of html.matchAll(/<form\b[^>]*>/g)) assert.ok(form[0].includes('novalidate'));
  const invalid=new Node();
  invalid.willValidate=true;invalid.validity={valid:false,valueMissing:true};invalid.attributes['aria-label']='账号';
  assert.equal(test.validateForm({elements:[invalid]},'login-error'),false);
  assert.equal(nodes['login-error'].textContent,'请填写账号');
  assert.equal(invalid.focused,true);
  invalid.validity={valid:true};assert.equal(test.validateForm({elements:[invalid]},'login-error'),true);
  console.log('PASS: blank login and inline validation without browser storage or dialogs.');

  test.render(state);
  await test.showHelp(clients[0]);
  assert.equal(nodes['connect-endpoint'].value,'https://sip.example.com/api/connect');
  assert.equal(nodes['connect-token'].value,'');
  assert.equal(nodes['generate-token'].textContent,'生成接入码');
  assert.equal(generation,0,'Opening must not generate or replace a code');
  await test.generateToken();
  const token=nodes['connect-token'].value;
  assert.ok(token);
  await test.copyField('connect-token');assert.equal(context.copied,token);
  nodes['help-dialog'].close();assert.equal(nodes['connect-token'].value,'');
  await test.showHelp(clients[0]);assert.equal(nodes['connect-token'].value,token);
  assert.equal(nodes['copy-token'].disabled,false);
  assert.equal(nodes['generate-token'].textContent,'生成新的');
  test.showLogin();assert.equal(nodes['connect-token'].value,'');
  test.render(state);await test.showHelp(clients[0]);assert.equal(nodes['connect-token'].value,token);
  const reloaded=createUI();reloaded.context.fetch=backend;reloaded.test.render(state);
  await reloaded.test.showHelp(clients[0]);assert.equal(reloaded.nodes['connect-token'].value,token);
  assert.equal(generation,1,'Reopen, relogin and reload only read the saved code');
  await test.showHelp(clients[1]);assert.equal(nodes['connect-token'].value,'');
  codes.set(3,{token:null,hasCode:true});
  await test.showHelp(clients[2]);
  assert.equal(nodes['connect-token'].placeholder,'旧接入码需重新生成');
  assert.equal(nodes['generate-token'].textContent,'生成新的');
  assert.equal(generation,1);
  state.settings.sipDomain='';
  await test.showHelp(clients[0]);assert.equal(nodes['connect-endpoint'].value,'https://127.0.0.1/api/connect');
  await test.generateToken();assert.notEqual(nodes['connect-token'].value,token);
  nodes['help-dialog'].close();
  console.log('PASS: saved codes survive reopen, relogin and page reload; legacy codes are never auto-rotated.');

  let finishOld;
  context.fetch=()=>new Promise(resolve=>{finishOld=resolve});
  const stale=test.showHelp(clients[0]);
  nodes['help-dialog'].close();
  context.fetch=backend;
  await test.showHelp(clients[1]);
  finishOld(response({endpoint:'https://old.example.com/api/connect',token:'stale',hasCode:true}));
  await stale;
  assert.equal(nodes['connect-token'].value,'');
  assert.equal(nodes['connect-endpoint'].value,'https://127.0.0.1/api/connect');
  context.fetch=async()=>{throw new Error('fixture network error')};
  await test.showHelp(clients[0]);
  assert.equal(nodes['generate-token'].disabled,true);
  assert.equal(nodes['connect-token'].value,'');
  assert.ok(nodes['connect-error'].textContent);
  nodes['help-dialog'].close();context.fetch=backend;
  console.log('PASS: stale loads and network failures do not expose another client code or rotate it.');

  calls.length=0;
  const button=new Node();
  let task=test.removeClient(clients[0],button);
  assert.equal(calls.length,0);assert.equal(nodes['confirm-cancel'].focused,true);
  nodes['confirm-dialog'].close();await task;
  assert.equal(calls.length,0);assert.equal(button.disabled,false);
  task=test.removeClient(clients[0],button);
  nodes['confirm-dialog'].close('confirm');
  vm.runInContext('refreshTask = null',context);
  await task;
  assert.deepEqual(calls[0],['/api/clients/1','DELETE']);
  assert.equal(calls.filter(call=>call[1]==='DELETE').length,1);
  assert.equal(button.disabled,false);
  console.log('PASS: delete cancellation is safe; confirmation sends one delete.');
}
main().catch(error=>{console.error(error);process.exitCode=1});
