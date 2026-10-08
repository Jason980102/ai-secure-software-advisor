'use strict';
const adviceCache = new WeakMap();
const advicePending = new WeakMap();
let aiAvailable = null;
let aiConfig = {};

function downloadText(text, filename, type='text/plain') {
 const url=URL.createObjectURL(new Blob([text],{type}));
 const anchor=node('a');anchor.href=url;anchor.download=filename;anchor.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}

function renderUpgradePlan(report) {
 const plan=report.upgrade_plan;
 if(!plan)return node('div');
 const card=node('section',undefined,'card upgrade-plan');card.id='upgrade-plan';
 card.append(node('h2',t('planTitle')),node('p',t('planIntro')),
     badge(t(plan.status==='review_required'?'planReview':'planTest'),plan.status==='review_required'?'unknown':''));
 const warnings=node('ul',undefined,'plan-warnings');
 for(const code of plan.warnings)warnings.append(node('li',t(code)));
 card.append(warnings);
 const table=node('table');const header=node('tr');
 for(const key of ['packageLabel','versionChange','actionLabel'])header.append(node('th',t(key)));
 table.append(header);
 for(const item of plan.items){const row=node('tr');
  const name=item.package+(item.extras.length?'['+item.extras.join(', ')+']':'');
  row.append(node('td',name),node('td',item.installed_version+' → '+item.proposed_version),node('td',t(item.action)));
  table.append(row);
 }
 const wrapper=node('div',undefined,'table-wrap');wrapper.append(table);card.append(wrapper);
 const button=node('button',t('planDownload'),'primary plan-download');button.id='download-plan';button.type='button';
 button.onclick=()=>downloadText(plan.requirements_text,'requirements.proposed.txt');card.append(button);
 const next=node('div',undefined,'next-steps');next.append(node('h3',t('nextTitle')));
 const steps=node('ol');for(const key of ['nextReview','nextTest','nextRescan'])steps.append(node('li',t(key)));
 next.append(steps);card.append(next);return card;
}

function renderAdvice(report) {
 const card=node('section',undefined,'card ai-card');card.id='ai-advice';
 card.append(node('h2',t('aiTitle')),node('p',t('aiIntro')));
 const limits=(report.upgrade_plan?.warnings||[]).filter(code=>['dependency_incomplete','dependency_conflicts','dependencies_not_checked'].includes(code));
 if(limits.length){const notes=node('ul',undefined,'plan-warnings');for(const code of limits)notes.append(node('li',t(code)));card.append(notes);}
 if(aiConfig.provider==='ollama')card.append(badge(t('aiLocal',{model:aiConfig.model||'Ollama'}),''));
 const result=adviceCache.get(report)?.[language];
 const pending=advicePending.get(report)?.has(language);
 if(result?.status==='generated'){
  card.append(node('p',result.content.summary,'ai-summary'));
  for(const item of result.content.packages){const section=node('div',undefined,'ai-package');
   section.append(node('h3',item.package));
   const source=report.results.find(p=>p.package===item.package);
   if(source){section.append(node('small',t('installed',{version:source.installed_version})));const facts=node('ul');for(const finding of source.vulnerabilities)facts.append(node('li',finding.id+' · '+(finding.severity||'UNKNOWN')));section.append(facts);}
   section.append(node('p',item.explanation),node('strong',t('testFocus')),node('p',item.test_focus));
   if(item.finding_ids.length)section.append(node('small',t('evidenceLabel')+': '+item.finding_ids.join(', ')));
   card.append(section);
  }
  const next=node('ol');for(const step of result.content.next_steps)next.append(node('li',step));card.append(next,node('p',t('aiCaution'),'hint'));
 }else{
  const message=pending?(aiConfig.provider==='ollama'?'aiLocalLoading':'aiLoading'):result?.status==='not_configured'||aiAvailable===false?'aiNotConfigured':result?.status==='unavailable'?'aiUnavailable':aiAvailable===null?'aiChecking':null;
  if(message){const status=node('p',t(aiConfig.reason&&aiAvailable===false?aiConfig.reason:message));status.setAttribute('role','status');card.append(status);}
  card.append(node('p',t(aiConfig.provider==='ollama'?'aiLocalPrivacy':'aiPrivacy'),'hint'));
  const button=node('button',t(pending?'aiLoading':'aiGenerate'),'secondary');button.id='generate-advice';button.type='button';
  button.disabled=Boolean(pending)||aiAvailable!==true;
  button.onclick=()=>requestAdvice(report,language);card.append(button);
  if(aiAvailable===false){const retry=node('button',t('aiRecheck'),'secondary');retry.type='button';retry.onclick=refreshAIConfig;card.append(retry);}
 }
 return card;
}

async function requestAdvice(report, requestedLanguage) {
 let pending=advicePending.get(report);if(!pending){pending=new Set();advicePending.set(report,pending);}
 if(pending.has(requestedLanguage))return;
 pending.add(requestedLanguage);render(report);
 let result;
 try{
  const response=await fetch('/api/v1/scan/advice',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({report,language:requestedLanguage})});
  if(!response.ok)throw new Error('Advice request failed');
  result=await response.json();
  if(!['generated','not_configured','unavailable'].includes(result.status))throw new Error('Invalid advice');
  if(result.status==='generated'&&(!result.content||!Array.isArray(result.content.packages)||!Array.isArray(result.content.next_steps)))throw new Error('Invalid advice content');
 }catch{result={status:'unavailable',language:requestedLanguage};}
 pending.delete(requestedLanguage);
 let cache=adviceCache.get(report);if(!cache){cache={};adviceCache.set(report,cache);}cache[requestedLanguage]=result;
 // A late response must never replace a newer scan or its language.
 if(savedReport===report&&language===requestedLanguage)render(report);
}

async function refreshAIConfig(){
 aiAvailable=null;if(savedReport)render(savedReport);
 try{const response=await fetch('/api/v1/scan/advice/config');if(!response.ok)throw new Error('Config unavailable');aiConfig=await response.json();aiAvailable=aiConfig.configured===true;}
 catch{aiAvailable=false;aiConfig={provider:'ollama',reason:'server_unavailable'};}
 if(savedReport)render(savedReport);
}
refreshAIConfig();

function reportNavigation(){
 const nav=node('nav',undefined,'report-navigation');nav.setAttribute('aria-label',t('reportNavigation'));
 for(const [id,key] of [['upgrade-plan','planTitle'],['ai-advice','aiTitle']]){
  const link=node('a',t(key),'secondary');link.href='#'+id;nav.append(link);
 }return nav;
}
