'use strict';
const $ = id => document.getElementById(id);
let savedReport = null;
let language = 'en';
try {const stored=localStorage.getItem('advisor-language');if(translations[stored])language=stored;} catch {}
function t(key, values={}) {let value=translations[language][key]||translations.en[key]||key;for(const [name,text] of Object.entries(values))value=value.replaceAll('{'+name+'}',String(text));return value;}
const messageKeys=new Map();
function setMessage(id,key){messageKeys.set(id,key);$(id).textContent=t(key);}
function applyLanguage(){document.documentElement.lang=language;$('language').value=language;$('language').setAttribute('aria-label',t('language'));document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=t(el.dataset.i18n));updateLabels();for(const [id,key]of messageKeys)$(id).textContent=t(key);if(savedReport)render(savedReport);}
const example = 'requests==2.19.0\nflask==2.0.0\nnumpy==1.21.0';
let labels;
function updateLabels(){labels = {candidate:t("升級候選"),not_needed:t("未發現已知漏洞"),manual_review:t("需要人工確認"),verification_failed:t("候選查驗失敗"),incomplete:t("依賴資訊尚未完整"),conflicts_found:t("發現依賴衝突"),no_direct_conflicts:t("範圍內未發現直接衝突"),satisfied:t("符合"),conflict:t("衝突"),missing:t("未提供版本"),unknown:t("未知"),skipped:t("不適用")};}
function node(tag, text, cls) {const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;}
function badge(text,kind){return node('span',text,'badge '+kind);}
function details(title,data){const d=node('details');d.append(node('summary',title),node('pre',JSON.stringify(data,null,2)));return d;}
function render(report){
 const root=$('report');root.replaceChildren();
 const head=node('div',undefined,'report-head');head.append(node('h2',t("掃描報告")));const download=node('button',t("下載 JSON"),'secondary');download.type='button';download.onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify({...savedReport,ai_advice:adviceCache.get(savedReport)?.[language]||null},null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download='scan-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};head.append(download);root.append(head);
 const metrics=node('div',undefined,'metrics');for(const [key,label]of [['total_packages',t("掃描套件")],['vulnerable_packages',t("有漏洞套件")],['total_vulnerabilities',t("原版本漏洞")]]){const m=node('div',undefined,'metric');m.append(node('strong',report[key]),node('span',label));metrics.append(m);}root.append(metrics);
 root.append(reportNavigation(),renderUpgradePlan(report),renderAdvice(report));
 const evidenceRoot=node('details',undefined,'technical-evidence');evidenceRoot.append(node('summary',t('technicalDetails')));root.append(evidenceRoot);
 if(report.dependency_check){const p=report.dependency_check;const card=node('section',undefined,'card plan');card.append(node('h3',t("升級計畫的直接依賴檢查")),node('p',t('plan',{status:labels[p.status]||p.status,conflicts:p.conflict_count,unresolved:p.unresolved_count})),node('p',t("未提供依賴版本不等於安裝失敗；沒有直接衝突也不代表完整環境可用。")));const wrap=node('div',undefined,'table-wrap');const table=node('table');for(const c of p.checks){const tr=node('tr');const from=node('td',`${c.package} ${c.selected_version}`);const req=node('td',c.requirement||t("依賴資料"));req.append(node('p',c.reason));const state=node('td');state.append(badge(labels[c.status]||c.status,c.status));tr.append(from,req,state);table.append(tr);}const d=node('details');d.append(node('summary',t("查看依賴條件明細")));wrap.append(table);d.append(wrap);card.append(d,details(t("查看選定版本"),p.selected_versions));evidenceRoot.append(card);}
 for(const p of report.results){const card=node('section',undefined,'card package');const head=node('div',undefined,'package-head');const title=node('div');title.append(node('h3',p.package+(p.extras?.length?'['+p.extras.join(', ')+']':'')),node('small',t('installed',{version:p.installed_version})));head.append(title,badge(t('findings',{count:p.vulnerabilities.length}),p.vulnerabilities.length?'HIGH':''));card.append(head);
 const u=p.upgrade_recommendation;const upgrade=node('div',undefined,'upgrade');upgrade.append(node('strong',`${labels[u.status]||u.status}${u.recommended_version?' → '+u.recommended_version:''}`));if(u.major_upgrade)upgrade.append(node('p',t("跨主要版本升級：請確認 API 變更並執行應用程式測試。")));if(u.candidate_source)upgrade.append(node('p',t('source',{source:t(u.candidate_source==='pypi_release'?'PyPI 擴大搜尋':'漏洞修補版本'),versions:u.checked_versions.join(', ')})));upgrade.append(node('p',u.reason));card.append(upgrade);
 if(p.vulnerabilities.length){const wrap=node('div',undefined,'table-wrap');const table=node('table');const row=node('tr');for(const text of [t("漏洞 / 說明"),t("嚴重程度"),t("修補版本")])row.append(node('th',text));table.append(row);for(const v of p.vulnerabilities){const tr=node('tr');const name=node('td',v.id);name.append(node('p',v.summary));const severity=node('td');severity.append(badge(v.severity||'UNKNOWN',v.severity||'UNKNOWN'));if(v.cvss_score!==null&&v.cvss_score!==undefined)severity.append(node('p',`CVSS ${v.cvss_score}`));tr.append(name,severity,node('td',v.fixed_versions.join(', ')||t("未提供")));table.append(tr);}wrap.append(table);card.append(wrap);}card.append(details(t("查看候選查驗依據"),u.release_checks));evidenceRoot.append(card);}
 evidenceRoot.append(details(t("完整 JSON 報告"),report));$('empty').hidden=true;root.hidden=false;
}
$('example').onclick=()=>{$('requirements').value=example;setMessage('filename',"已載入三套件範例（只作掃描輸入）");};
$('file').onchange=async event=>{const file=event.target.files[0];if(!file)return;try{if(file.size>400000)throw new Error(t("檔案過大，請使用小於 400 KB 的文字檔。"));const text=await file.text();if(text.length>100000)throw new Error(t("內容超過 100,000 字元。"));$('requirements').value=text;messageKeys.delete('filename');$('filename').textContent=file.name;$('error').hidden=true;}catch(e){messageKeys.delete('error');$('error').textContent=e.message;$('error').hidden=false;}};
$('scan-form').onsubmit=async event=>{
 event.preventDefault();const python=$('python').value.trim(),platform=$('platform').value;if(platform&&!python){setMessage('error',"檢查平台 wheel 時，請填寫完整 Python 版本，例如 3.12.0。");$('error').hidden=false;return;}
 const payload={requirements:$('requirements').value,check_dependencies:$('dependencies').checked};if(python)payload.target_python=python;if(platform)payload.target_platform=platform;
 $('submit').disabled=true;$('example').disabled=true;$('error').hidden=true;setMessage('status',"正在查詢 OSV 與 PyPI；套件較多時可能需要等待。");$('results').setAttribute('aria-busy','true');$('report').hidden=true;$('empty').hidden=false;savedReport=null;
 try{const response=await fetch('/api/v1/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});let data;try{data=await response.json();}catch{throw new Error(t("伺服器沒有回傳有效 JSON，請確認後端狀態。"));}if(!response.ok){const detail=Array.isArray(data.detail)?data.detail.map(e=>`${e.loc?.join('.')||'input'}: ${e.msg}`).join('\n'):data.detail;throw new Error(detail||t('http',{code:response.status}));}if(!Array.isArray(data.results))throw new Error(t("報告格式不符合預期。"));savedReport=data;render(data);setMessage('status',"掃描完成。統計描述原版本；升級候選仍需實際測試。");}
 catch(e){messageKeys.delete('error');if(e instanceof TypeError)setMessage('error','無法連線到後端，請確認服務已啟動後重試。');else $('error').textContent=e.message;$('error').hidden=false;setMessage('status',"本次掃描未完成。");}
 finally{$('submit').disabled=false;$('example').disabled=false;$('results').setAttribute('aria-busy','false');}
};

$('language').onchange=()=>{language=$('language').value;try{localStorage.setItem('advisor-language',language);}catch{}applyLanguage();};
applyLanguage();
