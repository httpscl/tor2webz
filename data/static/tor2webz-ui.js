(()=>{
"use strict";
const termsBack=document.getElementById('terms-back');
if(termsBack)termsBack.addEventListener('click',()=>{const navigation=window.navigation;const previous=navigation?.entries().find(entry=>entry.index===navigation.currentEntry.index-1);if(previous?.url&&new URL(previous.url).origin===window.location.origin)window.history.back();else window.location.assign('https://onion.https.cl/');});
document.querySelectorAll('[data-open]').forEach(button=>button.addEventListener('click',()=>document.getElementById(button.dataset.open).showModal()));
document.querySelectorAll('[data-close]').forEach(button=>button.addEventListener('click',()=>document.getElementById(button.dataset.close).close()));
const gateway=document.getElementById('gateway');
if(gateway)gateway.addEventListener('submit',event=>{event.preventDefault();const value=document.getElementById('onion').value.trim();const match=/^(?:https?:\/\/)?([a-z2-7]{56})(?:\.onion)?((?:[/?#][^\s]*)?)$/i.exec(value);if(!match){document.getElementById('gateway-error').textContent='Ingresa una dirección onion v3 de 56 caracteres.';return;}window.location.assign('https://'+match[1].toLowerCase()+'.onion.https.cl'+(match[2]||'/'));});
const accept=document.getElementById('accept-disclaimer');
if(accept)accept.addEventListener('click',()=>{document.cookie='disclaimer_accepted=true; Path=/; Secure; SameSite=Lax';window.location.reload();});


const contactForm=document.getElementById('contact-form');
if(contactForm){
 const button=document.getElementById('contact-submit');const status=document.getElementById('contact-status');
 const kind=document.getElementById('contact-kind');const reportUrl=document.getElementById('abuse-url');
 const updateKind=()=>{const abuse=kind.value==='abuse';document.getElementById('contact-destination').textContent=abuse?'abuse@https.cl':'contacto@https.cl';document.getElementById('abuse-url-field').hidden=!abuse;document.getElementById('abuse-notice').hidden=!abuse;reportUrl.disabled=!abuse;reportUrl.required=abuse;};
 kind.addEventListener('change',updateKind);updateKind();
 const checkContact=async()=>{try{const r=await fetch('/__tor2webz/contact',{cache:'no-store'});const d=await r.json();button.disabled=!d.ready;button.textContent=d.ready?'Enviar mensaje':'Envío temporalmente no disponible';}catch{button.disabled=true;button.textContent='Envío temporalmente no disponible';}};
 document.querySelector('[data-open="contact"]').addEventListener('click',checkContact);
 if(new URLSearchParams(window.location.search).get('contact')==='abuse'){
  kind.value='abuse';kind.dispatchEvent(new Event('change'));
  const reported=new URLSearchParams(window.location.hash.slice(1)).get('url');
  if(reported&&reported.length<=2048&&!/[\s\x00-\x1f\x7f\\]/.test(reported)){
   try{const parsed=new URL(reported);if(['http:','https:'].includes(parsed.protocol)&&!parsed.username&&!parsed.password)reportUrl.value=reported;}catch{}
  }
  document.getElementById('contact').showModal();checkContact();
 }
 contactForm.addEventListener('submit',async event=>{event.preventDefault();button.disabled=true;button.textContent='Enviando';status.textContent='';const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),12000);try{const r=await fetch('/__tor2webz/contact',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind:kind.value,url:kind.value==='abuse'?reportUrl.value.trim():'',email:document.getElementById('contact-email').value,message:document.getElementById('contact-message').value,website:document.getElementById('contact-website').value}),signal:controller.signal});const d=await r.json();if(!r.ok||!d.sent){status.textContent=r.status===429?'Espera un minuto antes de volver a enviar.':r.status===400?'Revisa los campos y la URL denunciada (http:// o https://).':'No se pudo entregar el mensaje. Intenta más tarde.';}else{status.textContent='Mensaje entregado al servidor de correo.';document.getElementById('contact-message').value='';}}catch{status.textContent='No se pudo entregar el mensaje. Intenta más tarde.';}finally{clearTimeout(timeout);button.disabled=false;button.textContent='Enviar mensaje';}});
}
})();
