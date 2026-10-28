(()=>{
"use strict";
const banner=document.getElementById('t2wz-banner');
const toggle=document.getElementById('t2wz-toggle');
if(!banner||!toggle)return;
const report=document.getElementById('t2wz-report-abuse');
if(report){
 const updateReport=()=>{const target=new URL('https://onion.https.cl/?contact=abuse');target.hash=new URLSearchParams({url:window.location.href}).toString();report.href=target.href;};
 updateReport();report.addEventListener('click',updateReport);
 report.addEventListener('contextmenu',updateReport);
 window.addEventListener('hashchange',updateReport);window.addEventListener('popstate',updateReport);
}
toggle.addEventListener('click',()=>{const collapsed=banner.classList.toggle('is-collapsed');toggle.textContent=collapsed?'Mostrar banner':'Ocultar banner';toggle.setAttribute('aria-expanded',String(!collapsed));});
})();
