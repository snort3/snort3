# 📝 Resumen: Utilidad y función principal

**Snort** es un sistema de detección y prevención de intrusiones (**IDS/IPS**) de código abierto, diseñado para proteger redes frente a amenazas como ataques **DDoS**. Utiliza un conjunto de reglas integradas que definen comportamientos maliciosos en la red, y analiza los paquetes en tiempo real para identificar coincidencias. Cuando detecta actividad sospechosa, genera alertas para los administradores.

Snort es capaz de identificar ataques recientes, infecciones de malware, sistemas comprometidos y violaciones de políticas de seguridad. Su motor de detección se basa en un lenguaje de reglas que combina inspección por anomalías, protocolos y firmas, lo que le permite detectar actividades potencialmente maliciosas con alta precisión.

**Snort 3** representa una evolución significativa respecto a versiones anteriores, destacando por su mayor rendimiento, flexibilidad y facilidad de mantenimiento.

### Función principal

Analizar el tráfico de red en tiempo real para detectar y bloquear amenazas como:

- Ataques de denegación de servicio (**DoS/DDoS**)
- Escaneos de puertos
- Desbordamientos de búfer
- Malware, phishing y spam

📘 Para más detalles sobre su instalación y la creación de reglas personalizadas, consulta el siguiente recurso oficial:  
[Using Snort - Snort 3 Rule Writing Guide](https://docs.snort.org/start/)

---

# 📝 Justificación

Se eligió el repositorio `snort3/snort3` en GitHub porque **Snort** se ha consolidado como uno de los sistemas de detección y prevención de intrusos (**IDS/IPS**) más utilizados a nivel mundial. Es empleado tanto por empresas como por usuarios individuales para proteger redes domésticas, corporativas y educativas.

El repositorio seleccionado es el principal y oficial del proyecto **Snort 3**, mantenido por el equipo de desarrollo original. Esto garantiza acceso directo a actualizaciones, correcciones de errores, nuevas funcionalidades y compatibilidad con estándares modernos.

Snort ofrece tres funcionalidades principales:

- Actuar como un rastreador de paquetes similar a `tcpdump`
- Funcionar como un registrador de paquetes útil para la depuración de tráfico
- Operar como un sistema completo de prevención de intrusiones en red

Además, Snort ha sido utilizado en diversos proyectos académicos que abordan la seguridad de redes desde enfoques prácticos y metodológicos. Por ejemplo:

- Un estudio de la **Universidad de Sevilla** analizó la capacidad de detección de ataques en red de Snort utilizando la matriz **MITRE ATT&CK** y la plataforma **Caldera**, demostrando su eficacia en entornos simulados (González et al., 2024).
- Una investigación reciente propone un sistema colaborativo distribuido, en el que múltiples nodos con Snort se conectan a un servidor central que emplea **SIEM** (como LogScale), mejorando la correlación en tiempo real y reduciendo falsos positivos. Este enfoque mostró alta efectividad en la detección de ataques distribuidos (Alvarez & Chen, 2025).

Estos proyectos evidencian que **Snort 3** está siendo activamente utilizado en investigaciones académicas para evaluar, comparar y fortalecer sistemas de detección de intrusos en redes modernas.

---

# ✅ Conclusión

La elección de **Snort 3** para este trabajo se fundamenta en la solidez, relevancia y evolución continua de la herramienta como sistema de detección y prevención de intrusiones. Es una solución útil, gratuita y respaldada por una comunidad activa, que permite fortalecer la seguridad de red de quienes la implementan.

---

# 📚 Referencias

- Alvarez, J., & Chen, L. (2025). *A collaborative intrusion detection system using Snort IDS nodes*. arXiv. https://arxiv.org/abs/2504.16550  
- González, M., Pérez, A., & Ruiz, D. (2024). *Evaluación de Snort bajo MITRE ATT&CK y Caldera*. Universidad de Sevilla.  
- Roesch, M. (1999). *Snort - Lightweight Intrusion Detection for Networks*. Proceedings of the 13th USENIX Conference on System Administration. https://www.snort.org

