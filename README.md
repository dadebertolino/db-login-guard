# DB Login Guard

Protezione brute force per WordPress. Registra i tentativi di login, blocca gli IP dopo troppi errori, notifica via email. Niente servizi esterni, niente abbonamenti.

**Versione:** 1.1.0  
**Autore:** [Davide Bertolino](https://www.davidebertolino.it)  
**Licenza:** GPL v2 or later  
**Richiede:** WordPress 5.8+ · PHP 7.4+  
**GitHub:** [dadebertolino/db-login-guard](https://github.com/dadebertolino/db-login-guard)

---

## Cosa fa

Monitora tutti i tentativi di accesso a `wp-login.php`. Dopo un numero configurabile di tentativi falliti dallo stesso IP, lo blocca temporaneamente. Registra tutto in un log consultabile dall'admin, con filtri e export CSV.

### Funzionalità

- **Blocco automatico** — dopo N tentativi falliti in X minuti, l'IP viene bloccato per Y minuti (tutto configurabile)
- **Log completo** — registra IP, username, user-agent, data/ora, stato (fallito/riuscito/bloccato) per ogni tentativo
- **Dashboard** — statistiche in tempo reale: tentativi falliti nelle ultime 24h, IP unici attaccanti, username più attaccato
- **Gestione IP bloccati** — tabella con sblocco manuale e blocco manuale
- **Whitelist IP** — lista di IP/CIDR che non vengono mai bloccati (per non chiuderti fuori)
- **Notifiche email** — email automatica quando un IP viene bloccato (con rate limiting: max 1 ogni 10 min per IP)
- **Export CSV** — scarica il log completo in CSV
- **Auto-pulizia** — WP Cron elimina i record più vecchi di N giorni
- **Avviso tentativi rimanenti** — nella pagina di login, mostra quanti tentativi restano prima del blocco
- **Rilevamento IP** — supporto Cloudflare (CF-Connecting-IP), X-Forwarded-For, X-Real-IP
- **Disabilitazione XML-RPC** — blocca xmlrpc.php con 403, rimuove header X-Pingback e link RSD/WLW, logga i tentativi
- **Protezione REST API /users** — blocca l'enumerazione utenti via /wp-json/wp/v2/users per visitatori anonimi
- **Disabilita XML-RPC** — blocca xmlrpc.php con 403, rimuove header X-Pingback e link RSD/WLW. Previene brute force via system.multicall
- **Proteggi REST API /users** — blocca l'endpoint /wp/v2/users per visitatori anonimi, impedendo l'enumerazione degli username. Gutenberg e utenti loggati funzionano normalmente

### Cosa NON fa

- Non modifica la pagina di login (per quello c'è DB Login Customizer)
- Non aggiunge CAPTCHA o 2FA
- Non comunica con servizi esterni
- Non ha versione Pro

---

## Installazione

1. Scarica il file ZIP dalla [release GitHub](https://github.com/dadebertolino/db-login-guard/releases)
2. WordPress Admin → Plugin → Aggiungi nuovo → Carica plugin → scegli il file ZIP
3. Attiva il plugin
4. Vai su **Strumenti → Login Guard**

### Primo utilizzo

Il plugin è attivo con valori predefiniti ragionevoli (5 tentativi in 10 minuti → blocco 30 minuti). Aggiungi il tuo IP alla whitelist per sicurezza.

---

## Configurazione

Il pannello si trova in **Strumenti → Login Guard** con 4 tab:

| Tab | Contenuto |
|-----|-----------|
| Dashboard | Statistiche, stato protezione, IP attuale |
| Log accessi | Tabella con filtri (stato, IP, username), paginazione, export CSV, svuota log |
| IP bloccati | Lista IP bloccati con sblocco manuale, blocco manuale |
| Impostazioni | Tentativi max, finestra temporale, durata blocco, whitelist, log, notifiche, hardening |

### Impostazioni predefinite

| Parametro | Valore |
|-----------|--------|
| Tentativi massimi | 5 |
| Finestra temporale | 10 minuti |
| Durata blocco | 30 minuti |
| Log login riusciti | Sì |
| Conservazione log | 30 giorni |
| Notifica email | Sì (all'email admin) |
| XML-RPC | Attivo (disattivabile) |
| REST API /users | Pubblico (bloccabile per anonimi) |

---

## Struttura cartelle

```
db-login-guard/
├── db-login-guard.php         # File principale + singleton
├── uninstall.php              # Pulizia completa
├── README.md
├── LICENSE
├── assets/
│   ├── css/
│   │   └── admin.css          # Stili pagina admin
│   └── js/
│       └── admin.js           # AJAX clear/export
└── inc/
    ├── class-database.php     # Tabelle, query, CRUD
    ├── class-guard.php        # Logica protezione + hook login
    ├── class-admin.php        # Pagina admin + AJAX
    ├── class-cron.php         # Auto-pulizia giornaliera
    └── class-hardening.php    # XML-RPC disable + REST API restriction
```

---

## Note tecniche

- Due tabelle custom: `{prefix}dblg_login_log` e `{prefix}dblg_blocked_ips`
- Tabelle create via `dbDelta()` + check just-in-time
- L'hook `authenticate` (priorità 1) blocca PRIMA che WordPress provi le credenziali — nessun carico sul database per IP bloccati
- Whitelist supporta CIDR (es: `192.168.1.0/24`)
- Rate limiting notifiche: max 1 email ogni 10 minuti per IP (via transient)
- L'uninstall rimuove tutto: tabelle, opzioni, transient, cron
- Nonce su tutti i form e AJAX, capability check `manage_options`
- L'utente vede quanti tentativi gli restano prima del blocco nella pagina di login
- XML-RPC: quando disabilitato, blocca a livello di `init` con 403 prima che WordPress processi la richiesta
- REST API: blocca solo `/wp/v2/users` per anonimi, tutti gli altri endpoint restano accessibili
- I tentativi bloccati su xmlrpc.php e REST /users vengono registrati nel log

---

## Sicurezza

- Nonce verification su ogni form e azione AJAX
- `current_user_can('manage_options')` su tutte le pagine admin
- `$wpdb->prepare()` su tutte le query con variabili
- `sanitize_text_field()` / `sanitize_key()` / `intval()` su tutti gli input
- `esc_html()` / `esc_attr()` / `esc_url()` su tutti gli output
- `if (!defined('ABSPATH')) exit;` su ogni file PHP
- Azioni distruttive (blocco/sblocco) gestite in `admin_init` prima dell'output

---

## Changelog

### 1.1.0
- 🆕 Opzione per disabilitare XML-RPC completamente (blocco 403 + rimozione header/link)
- 🆕 Opzione per bloccare REST API /users per utenti anonimi
- 🆕 Sezione Hardening nella dashboard con stato XML-RPC e REST API
- 🆕 I tentativi su xmlrpc.php e REST /users vengono registrati nel log
- Nuova classe `DBLG_Hardening` per separare la logica di hardening

### 1.0.0
- Release iniziale
- Blocco automatico IP dopo N tentativi falliti
- Log accessi con filtri e paginazione
- Dashboard con statistiche 24h
- Gestione IP bloccati (blocco/sblocco manuale)
- Whitelist IP con supporto CIDR
- Notifiche email con rate limiting
- Export CSV log
- Auto-pulizia via WP Cron
- Avviso tentativi rimanenti nella pagina di login

---

## Licenza

GPL v2 or later — sei libero di utilizzare, modificare e distribuire questo plugin.

---

## Autore

**Davide Bertolino**  
🌐 [davidebertolino.it](https://www.davidebertolino.it)  
📧 info@davidebertolino.it
