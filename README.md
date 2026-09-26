# DB Login Guard

Protezione brute force per WordPress. Registra i tentativi di login, blocca gli IP dopo troppi errori, notifica via email. Niente servizi esterni, niente abbonamenti.

**Versione:** 1.2.0  
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
│   │   ├── db-admin-ui.css    # Design system admin condiviso (plugin DB)
│   │   └── admin.css          # Stili pagina admin
│   └── js/
│       └── admin.js           # AJAX clear/export
└── inc/
    ├── class-database.php     # Tabelle, query, CRUD
    ├── class-guard.php        # Logica protezione + hook login
    ├── class-admin.php        # Pagina admin + AJAX
    ├── class-cron.php         # Auto-pulizia giornaliera (retention + blocchi scaduti)
    ├── class-hardening.php    # XML-RPC disable + REST API restriction
    ├── class-privacy-declarations.php  # Registro trattamenti (DB Privacy Hub)
    ├── class-privacy-dsar.php # Export / cancellazione dati personali (art. 15/17)
    └── class-updater.php      # Auto-aggiornamento da GitHub Releases
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

## Integrazione ecosistema DB privacy

Quando uno o più plugin della suite privacy (DB Privacy Hub, DB SEO Manager) sono installati, DB Login Guard li sfrutta automaticamente — senza configurazione. Senza di essi il plugin funziona identico e resta conforme tramite i filter core di WordPress.

### Cosa viene trattato

| Dato | Dove | Come | Conservazione |
|---|---|---|---|
| Indirizzo IP | `{prefix}dblg_login_log`, `{prefix}dblg_blocked_ips` | in chiaro (serve al conteggio/blocco per IP) | log: N giorni (impostazione, default 30); blocchi: fino alla scadenza + pulizia giornaliera |
| Nome utente / email digitati | `{prefix}dblg_login_log` | testo digitato nel form, anche se errato | come sopra |
| User agent | `{prefix}dblg_login_log` | troncato a 500 caratteri | come sopra |
| Password | — | **mai** registrate | — |

Base giuridica: legittimo interesse alla sicurezza del sito (art. 6.1.f GDPR). La pulizia è eseguita dall'evento WP-Cron giornaliero `dblg_cleanup_logs`, schedulato in modo idempotente a ogni `init` (non più solo in attivazione) e rimosso in disattivazione/disinstallazione. I giorni di conservazione si impostano in **Strumenti → Login Guard → Impostazioni → Log** oppure via filter:

```php
add_filter( 'dblg_log_retention_days', function () { return 90; } ); // 0 = nessuna pulizia automatica
```

### Dichiarazione trattamenti al registro privacy unificato

Quando **DB Privacy Hub 1.0.0+** è installato (o DB SEO Manager 1.2.x tramite il filter legacy `dbseo_processing_register`), DB Login Guard dichiara automaticamente i suoi trattamenti in "Privacy → Registro trattamenti", con testi che riflettono la configurazione reale (login riusciti registrati sì/no, giorni di conservazione, durata blocco).

| ID | Quando appare |
|---|---|
| `dblg_login_log` | sempre (`inactive` se la protezione è disattivata) |
| `dblg_blocked_ips` | sempre (`inactive` se la protezione è disattivata) |
| `dblg_block_notification` | protezione attiva + notifiche email attive |

### DSAR routing via Privacy Hub

Export e cancellazione passano per **Strumenti → Esporta / Cancella dati personali** di WordPress, con doppio canale:

- **Con DB Privacy Hub**: exporter/eraser registrati su `dbph_user_data_exporters` / `dbph_user_data_erasers` (l'Hub li riporta sui filter core e li traccia nello Storico DSAR).
- **Senza Hub**: registrazione diretta su `wp_privacy_personal_data_exporters` / `_erasers` (saltata se esiste `DBPH_DSAR`, per evitare doppioni).

Il log non ha `user_id`: una riga è attribuita all'interessato se il campo username coincide (senza distinzione maiuscole/minuscole) con l'**email** della richiesta oppure con lo **user_login** dell'account WordPress associato a quell'email. Le righe `xmlrpc` / `rest-api` dell'hardening non sono riferite a persone e sono escluse. Batch da 100 righe con paginazione `done` corretta.

**Cancellazione = anonimizzazione**: username → `[deleted]` (stringa del core, tradotta), IP troncato con `wp_privacy_anonymize_ip()` (es. `192.168.1.0`), user agent svuotato. Restano solo esito, codice errore e data/ora: non identificano più nessuno ma mantengono coerenti le statistiche di sicurezza. La tabella degli IP bloccati non contiene username, non è collegabile all'interessato e non viene toccata (i blocchi scadono da soli).

### Marker `DBLG_DSAR_AVAILABLE`

Il file principale definisce `DBLG_DSAR_AVAILABLE = true` e un blocco "Privacy capabilities" che riassume cosa il plugin tratta. Il generatore di Privacy Policy dell'Hub rileva comunque la procedura DSAR tramite l'exporter registrato su `dbph_user_data_exporters`.

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

### 1.2.0 — Integrazione ecosistema DB privacy (registro trattamenti + DSAR)

**Registro trattamenti (DB Privacy Hub / DB SEO Manager):**
- Nuova classe `DBLG_Privacy_Declarations` agganciata a `dbph_processing_register` e al legacy `dbseo_processing_register` (dedup per `id` lato Hub).
- 3 voci dinamiche con tutti gli 8 campi: `dblg_login_log`, `dblg_blocked_ips`, `dblg_block_notification` (solo con notifiche attive). Base giuridica: legittimo interesse, sicurezza (art. 6.1.f GDPR).
- `data_collected` dichiara esattamente cosa è salvato: IP in chiaro (e da quali header), username digitato anche se errato, user agent troncato a 500 caratteri, esito, codice errore, data/ora; password mai registrate.

**DSAR (art. 15/17 GDPR):**
- Nuova classe `DBLG_Privacy_DSAR`, doppio canale: `dbph_user_data_exporters`/`_erasers` (chiave `label`) + fallback `wp_privacy_personal_data_*` (chiavi `*_friendly_name`) disattivato se esiste `DBPH_DSAR`.
- Match case-insensitive su email della richiesta e `user_login` dell'account collegato; righe sentinella `xmlrpc`/`rest-api` escluse.
- Export paginato (100 righe, `done` sul batch SQL). Cancellazione = anonimizzazione di username/IP/user agent, forme di ritorno identiche al core (`items_removed`/`items_retained` booleani, `messages`, `done`) e uscita sicura in caso di errore DB (niente loop infiniti).
- Marker `DBLG_DSAR_AVAILABLE` + blocco "Privacy capabilities" nel file principale.

**Conservazione dati:**
- L'evento WP-Cron `dblg_cleanup_logs` ora è schedulato in modo idempotente a ogni `init` (prima solo in attivazione: dopo un aggiornamento senza riattivazione la pulizia poteva non girare).
- Nuovo filter `dblg_log_retention_days` (0 = nessuna pulizia automatica); default invariato 30 giorni.

**Componenti condivisi:**
- Aggiunto `DB_GitHub_Updater` (`inc/class-updater.php`, init protetto da `class_exists`) e il design system `assets/css/db-admin-ui.css` come dipendenza di `admin.css`.
- CI GitHub Actions: `php -l` su PHP 7.4 e 8.3; workflow Release su tag `v*` con verifica tag = header = `DBLG_VERSION` e ZIP con cartella radice `db-login-guard/` senza file di sviluppo.

**Nessun breaking change.** Schema tabelle, opzioni e comportamento di blocco invariati.

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
