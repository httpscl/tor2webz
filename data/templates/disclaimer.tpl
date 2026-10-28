<html lang="es" xmlns:t="http://twistedmatrix.com/ns/twisted.web.template/0.1">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="theme-color" content="#0a0a0a"/>
<meta name="robots" content="noindex,nofollow"/>
<link rel="icon" href="/static/favicon.ico"/>
<link rel="stylesheet" href="/static/tor2webz-site.css"/>
<title>TOR2WEBZ | Antes de continuar</title>
</head>
<body>
<div class="page">
<header class="site-header">
<span class="brand">
<img src="/static/tor2webz-logo.png?v=f1fd6842" width="1014" height="228" alt="TOR2WEBZ"/>
</span>
</header>
<main>
<section class="access-panel">
<header class="panel-header">
<span class="panel-title">TOR2WEBZ / Funcionamiento del servicio</span>
<span class="panel-status">ONION V3</span>
</header>
<div class="panel-body">
<h1>Antes de entrar.</h1>
<p class="intro">Vas a abrir el servicio <strong class="host-name">
<t:transparent t:render="t2wvar-onion"/>.onion</strong> a través de TOR2WEBZ.</p>
<ol class="steps">
<li class="step">
<span class="step-number">01</span>
<span class="step-copy">
<strong>TOR2WEBZ no aloja este contenido</strong>
<span>Este servidor actúa únicamente como proxy para facilitar el acceso a contenido alojado dentro de la red Tor.</span>
</span>
</li>
<li class="step">
<span class="step-number">02</span>
<span class="step-copy">
<strong>El sitio de origen administra su contenido</strong>
<span>Las páginas que verás son publicadas por el servicio onion, no por TOR2WEBZ.</span>
</span>
</li>
<li class="step">
<span class="step-number">03</span>
<span class="step-copy">
<strong>Esta pasarela no proporciona anonimato</strong>
<span>La pasarela puede ver tu IP y las solicitudes. Para navegar con las protecciones de Tor, utiliza Tor Browser directamente.</span>
</span>
</li>
</ol>
<button class="reload-button" id="accept-disclaimer" type="button">Entendido, continuar</button>
<p class="copyright">Proyecto basado en el trabajo original de Aaron Swartz, Virgil Griffith y Hermes Center.</p>
</div>
</section>
</main>
<footer class="site-footer">
<span>HTTPS.CL | TOR2WEBZ · ONION V3 GATEWAY</span>
</footer>
</div>
<script src="/static/tor2webz-ui.js" defer="defer">
</script>
</body>
</html>