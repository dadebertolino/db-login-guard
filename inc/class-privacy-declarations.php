<?php
/**
 * DBLG_Privacy_Declarations — dichiarazione dei trattamenti al registro
 * privacy unificato del DB Privacy Hub (`dbph_processing_register`) e, per
 * retrocompatibilità, al filter legacy di DB SEO Manager
 * (`dbseo_processing_register`). L'Hub deduplica per `id`.
 *
 * Le voci sono dinamiche: descrivono la configurazione effettiva (log dei
 * login riusciti on/off, giorni di conservazione, notifiche email on/off).
 * Se nessun plugin privacy è installato i filter non vengono mai applicati:
 * nessun effetto collaterale.
 *
 * @package DBLG
 * @since   1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'DBLG_Privacy_Declarations' ) ) {

	/**
	 * Dichiarazioni trattamenti di DB Login Guard.
	 */
	class DBLG_Privacy_Declarations {

		/**
		 * Aggancia i filter del registro trattamenti.
		 */
		public static function init() {
			add_filter( 'dbph_processing_register', array( __CLASS__, 'declare_processing' ), 10, 1 );
			add_filter( 'dbseo_processing_register', array( __CLASS__, 'declare_processing' ), 10, 1 );
		}

		/**
		 * Aggiunge le voci di DB Login Guard al registro.
		 *
		 * @param array $register Voci già dichiarate.
		 * @return array
		 */
		public static function declare_processing( $register ) {
			if ( ! is_array( $register ) ) {
				$register = array();
			}

			$enabled = (bool) DB_Login_Guard::get_option( 'dblg_enabled' );
			$status  = $enabled ? 'active' : 'inactive';

			$register[] = self::build_log_entry( $status );
			$register[] = self::build_blocked_entry( $status );

			if ( $enabled && DB_Login_Guard::get_option( 'dblg_email_notify' ) ) {
				$register[] = self::build_notify_entry();
			}

			return $register;
		}

		/**
		 * Testo di conservazione del log in base alla configurazione reale.
		 *
		 * @return string
		 */
		private static function log_retention_text() {
			$days = DBLG_Cron::get_retention_days();

			if ( $days <= 0 ) {
				return __( 'Nessuna cancellazione automatica (conservazione disattivata via filter dblg_log_retention_days): i record restano finché l\'amministratore non svuota il log da Strumenti → Login Guard. Alla disinstallazione del plugin la tabella viene eliminata.', 'db-login-guard' );
			}

			return sprintf(
				/* translators: %d: giorni di conservazione del log. */
				__( '%d giorni. Un evento WP-Cron giornaliero (dblg_cleanup_logs) elimina i record più vecchi; l\'amministratore può svuotare il log in qualsiasi momento. Alla disinstallazione del plugin la tabella viene eliminata.', 'db-login-guard' ),
				$days
			);
		}

		/**
		 * Voce: log dei tentativi di accesso.
		 *
		 * @param string $status Stato della voce.
		 * @return array
		 */
		private static function build_log_entry( $status ) {
			$log_success = (bool) DB_Login_Guard::get_option( 'dblg_log_successful' );

			$scope = $log_success
				? __( 'Vengono registrati i tentativi falliti, quelli respinti perché l\'IP è bloccato e anche i login riusciti.', 'db-login-guard' )
				: __( 'Vengono registrati i tentativi falliti e quelli respinti perché l\'IP è bloccato (i login riusciti NON sono registrati).', 'db-login-guard' );

			return array(
				'id'             => 'dblg_login_log',
				'label'          => __( 'Log dei tentativi di accesso (DB Login Guard)', 'db-login-guard' ),
				'status'         => $status,
				'purpose'        => __( 'Proteggere l\'area di accesso del sito da attacchi brute force: contare i tentativi falliti per indirizzo IP, bloccare temporaneamente gli IP che superano la soglia e consentire all\'amministratore di analizzare gli accessi.', 'db-login-guard' ),
				'legal_basis'    => __( 'Legittimo interesse del titolare alla sicurezza del sito e dei sistemi informatici (art. 6.1.f GDPR; considerando 49).', 'db-login-guard' ),
				'data_collected' => sprintf(
					/* translators: %s: ambito della registrazione. */
					__( 'Tabella {prefix}dblg_login_log nel database WordPress: indirizzo IP in chiaro (non anonimizzato né hashato, necessario per il conteggio e il blocco per IP; letto da CF-Connecting-IP, X-Forwarded-For, X-Real-IP o REMOTE_ADDR), nome utente o email digitati nel modulo di accesso (anche se errati o inesistenti), user agent del browser (troncato a 500 caratteri), esito (fallito/riuscito/bloccato), codice di errore e data/ora. Le password NON vengono mai registrate. %s Vengono registrati anche i tentativi respinti su xmlrpc.php e REST /wp/v2/users quando l\'hardening è attivo.', 'db-login-guard' ),
					$scope
				),
				'retention'      => self::log_retention_text(),
				'transfers'      => __( 'Nessuno. I dati restano nel database WordPress locale; il plugin non contatta servizi esterni. L\'export CSV è disponibile solo agli amministratori.', 'db-login-guard' ),
			);
		}

		/**
		 * Voce: elenco degli IP bloccati.
		 *
		 * @param string $status Stato della voce.
		 * @return array
		 */
		private static function build_blocked_entry( $status ) {
			return array(
				'id'             => 'dblg_blocked_ips',
				'label'          => __( 'Blocco temporaneo degli IP (DB Login Guard)', 'db-login-guard' ),
				'status'         => $status,
				'purpose'        => __( 'Impedire nuovi tentativi di accesso dagli indirizzi IP che hanno superato il numero massimo di tentativi falliti.', 'db-login-guard' ),
				'legal_basis'    => __( 'Legittimo interesse del titolare alla sicurezza del sito (art. 6.1.f GDPR).', 'db-login-guard' ),
				'data_collected' => __( 'Tabella {prefix}dblg_blocked_ips: indirizzo IP in chiaro, numero di tentativi falliti, data/ora di blocco e di scadenza. Nessun nome utente è associato al blocco.', 'db-login-guard' ),
				'retention'      => sprintf(
					/* translators: %d: durata del blocco in minuti. */
					__( 'Il blocco dura %d minuti; i blocchi scaduti vengono eliminati dall\'evento WP-Cron giornaliero (dblg_cleanup_logs). L\'amministratore può sbloccare un IP in qualsiasi momento.', 'db-login-guard' ),
					absint( DB_Login_Guard::get_option( 'dblg_lockout_minutes' ) )
				),
				'transfers'      => __( 'Nessuno. Database WordPress locale.', 'db-login-guard' ),
			);
		}

		/**
		 * Voce: email di notifica all'amministratore.
		 *
		 * @return array
		 */
		private static function build_notify_entry() {
			return array(
				'id'             => 'dblg_block_notification',
				'label'          => __( 'Notifica email di blocco IP (DB Login Guard)', 'db-login-guard' ),
				'status'         => 'active',
				'purpose'        => __( 'Avvisare l\'amministratore quando un indirizzo IP viene bloccato per troppi tentativi di accesso falliti.', 'db-login-guard' ),
				'legal_basis'    => __( 'Legittimo interesse del titolare alla sicurezza del sito (art. 6.1.f GDPR).', 'db-login-guard' ),
				'data_collected' => __( 'Il testo dell\'email contiene l\'indirizzo IP bloccato, l\'ultimo nome utente tentato, il numero di tentativi, la durata del blocco e la data/ora. Per il rate limiting (max 1 email ogni 10 minuti per IP) viene salvato un transient con l\'hash MD5 dell\'IP.', 'db-login-guard' ),
				'retention'      => __( 'Il plugin non conserva copia dell\'email; il transient di rate limiting scade dopo 10 minuti. La conservazione dell\'email ricevuta dipende dalla casella dell\'amministratore.', 'db-login-guard' ),
				'transfers'      => __( 'L\'email viene inviata tramite wp_mail() all\'indirizzo configurato (default: email amministratore): transita dal server di posta / provider SMTP configurato sul sito.', 'db-login-guard' ),
			);
		}
	}
}
