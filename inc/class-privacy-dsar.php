<?php
/**
 * DBLG_Privacy_DSAR — diritto di accesso (art. 15 GDPR) e alla cancellazione
 * (art. 17 GDPR) sul log accessi di DB Login Guard, tramite la macchina
 * nativa di WordPress (Strumenti → Esporta / Cancella dati personali).
 *
 * Doppio canale:
 *  1. `dbph_user_data_exporters` / `dbph_user_data_erasers` (DB Privacy Hub,
 *     chiave `label`): canale primario, l'Hub li ribalta sui filter core.
 *  2. `wp_privacy_personal_data_exporters` / `_erasers` (core, chiavi
 *     `*_friendly_name`): fallback attivo solo se l'Hub NON è presente
 *     (`class_exists( 'DBPH_DSAR' )`), per evitare la doppia registrazione.
 *
 * Matching: il log non ha user_id, solo il testo digitato nel campo
 * "Nome utente o indirizzo email". Una riga appartiene all'interessato se
 * `LOWER(username)` coincide con l'email della richiesta OPPURE con lo
 * user_login dell'account WordPress con quell'email (get_user_by('email')).
 * I valori sentinella scritti dall'hardening ('xmlrpc', 'rest-api') non
 * identificano persone e sono esclusi.
 *
 * Cancellazione = anonimizzazione (scelta motivata): le righe non vengono
 * eliminate ma private di ogni dato personale (username → "[deleted]", IP
 * troncato con wp_privacy_anonymize_ip(), user agent svuotato). Restano
 * esito, codice di errore e data/ora, che non identificano più nessuno ma
 * mantengono coerenti le statistiche di sicurezza (conteggi falliti/riusciti/
 * bloccati) nell'interesse legittimo del titolare. Il risultato per
 * l'interessato equivale alla cancellazione (considerando 26 GDPR).
 * La tabella degli IP bloccati non contiene nomi utente, non è collegabile
 * all'interessato e non viene toccata (i blocchi scadono da soli).
 *
 * @package DBLG
 * @since   1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'DBLG_Privacy_DSAR' ) ) {

	/**
	 * Exporter / eraser del log accessi.
	 */
	class DBLG_Privacy_DSAR {

		/**
		 * Righe elaborate per ogni chiamata del callback.
		 */
		const BATCH_SIZE = 100;

		/**
		 * Chiave di registrazione (uguale sui due canali).
		 */
		const SLUG = 'db-login-guard';

		/**
		 * Valori di `username` scritti da DBLG_Hardening, non riferiti a persone.
		 *
		 * @var string[]
		 */
		private static $sentinels = array( 'xmlrpc', 'rest-api' );

		/**
		 * Aggancia i filter dei due canali.
		 */
		public static function init() {
			add_filter( 'dbph_user_data_exporters', array( __CLASS__, 'register_exporter_via_hub' ) );
			add_filter( 'dbph_user_data_erasers', array( __CLASS__, 'register_eraser_via_hub' ) );

			add_filter( 'wp_privacy_personal_data_exporters', array( __CLASS__, 'register_exporter' ) );
			add_filter( 'wp_privacy_personal_data_erasers', array( __CLASS__, 'register_eraser' ) );
		}

		/**
		 * Etichetta comune.
		 *
		 * @return string
		 */
		private static function label() {
			return __( 'DB Login Guard — Log accessi', 'db-login-guard' );
		}

		/* === Canale Hub === */

		/**
		 * @param array $exporters Exporter registrati sull'Hub.
		 * @return array
		 */
		public static function register_exporter_via_hub( $exporters ) {
			$exporters[ self::SLUG ] = array(
				'label'    => self::label(),
				'callback' => array( __CLASS__, 'exporter_callback' ),
			);
			return $exporters;
		}

		/**
		 * @param array $erasers Eraser registrati sull'Hub.
		 * @return array
		 */
		public static function register_eraser_via_hub( $erasers ) {
			$erasers[ self::SLUG ] = array(
				'label'    => self::label(),
				'callback' => array( __CLASS__, 'eraser_callback' ),
			);
			return $erasers;
		}

		/* === Fallback core WordPress === */

		/**
		 * @param array $exporters Exporter core.
		 * @return array
		 */
		public static function register_exporter( $exporters ) {
			if ( class_exists( 'DBPH_DSAR' ) ) {
				return $exporters; // L'Hub registra già tramite dbph_*.
			}
			$exporters[ self::SLUG ] = array(
				'exporter_friendly_name' => self::label(),
				'callback'               => array( __CLASS__, 'exporter_callback' ),
			);
			return $exporters;
		}

		/**
		 * @param array $erasers Eraser core.
		 * @return array
		 */
		public static function register_eraser( $erasers ) {
			if ( class_exists( 'DBPH_DSAR' ) ) {
				return $erasers;
			}
			$erasers[ self::SLUG ] = array(
				'eraser_friendly_name' => self::label(),
				'callback'             => array( __CLASS__, 'eraser_callback' ),
			);
			return $erasers;
		}

		/* === Matching === */

		/**
		 * Identificativi (minuscoli) con cui l'interessato può comparire nel log.
		 *
		 * @param string $email_address Email della richiesta DSAR.
		 * @return string[]
		 */
		private static function identifiers( $email_address ) {
			$email = strtolower( trim( (string) $email_address ) );
			if ( '' === $email ) {
				return array();
			}

			$ids  = array( $email );
			$user = get_user_by( 'email', $email );
			if ( $user && '' !== $user->user_login ) {
				$ids[] = strtolower( $user->user_login );
			}

			$ids = array_diff( array_unique( $ids ), self::$sentinels );
			return array_values( $ids );
		}

		/**
		 * Clausola WHERE con un placeholder %s per ogni identificativo.
		 *
		 * @param string[] $ids Identificativi minuscoli.
		 * @return string
		 */
		private static function where_clause( $ids ) {
			return 'LOWER(username) IN (' . implode( ', ', array_fill( 0, count( $ids ), '%s' ) ) . ')';
		}

		/* === Callback (comuni ai due canali) === */

		/**
		 * Exporter: restituisce le righe del log riferite all'interessato.
		 *
		 * @param string $email_address Email della richiesta.
		 * @param int    $page          Pagina (da 1).
		 * @return array{data: array, done: bool}
		 */
		public static function exporter_callback( $email_address, $page = 1 ) {
			global $wpdb;

			$ids = self::identifiers( $email_address );
			if ( empty( $ids ) ) {
				return array(
					'data' => array(),
					'done' => true,
				);
			}

			$page   = max( 1, (int) $page );
			$table  = $wpdb->prefix . 'dblg_login_log';
			$where  = self::where_clause( $ids );
			$offset = ( $page - 1 ) * self::BATCH_SIZE;

			$args = array_merge( $ids, array( self::BATCH_SIZE, $offset ) );

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders, WordPress.DB.DirectDatabaseQuery -- $table interno, $where contiene solo placeholder.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table WHERE $where ORDER BY id ASC LIMIT %d OFFSET %d", $args ) );
			$rows = is_array( $rows ) ? $rows : array();

			$statuses = array(
				'failed'  => __( 'Fallito', 'db-login-guard' ),
				'success' => __( 'Riuscito', 'db-login-guard' ),
				'blocked' => __( 'Bloccato', 'db-login-guard' ),
			);

			$data = array();
			foreach ( $rows as $row ) {
				$data[] = array(
					'group_id'          => 'db-login-guard-log',
					'group_label'       => self::label(),
					'group_description' => __( 'Tentativi di accesso registrati da DB Login Guard per la protezione brute force.', 'db-login-guard' ),
					'item_id'           => 'dblg-log-' . (int) $row->id,
					'data'              => array(
						array(
							'name'  => __( 'Data/ora', 'db-login-guard' ),
							'value' => $row->created_at,
						),
						array(
							'name'  => __( 'Esito', 'db-login-guard' ),
							'value' => isset( $statuses[ $row->status ] ) ? $statuses[ $row->status ] : $row->status,
						),
						array(
							'name'  => __( 'Nome utente / email digitati', 'db-login-guard' ),
							'value' => $row->username,
						),
						array(
							'name'  => __( 'Indirizzo IP', 'db-login-guard' ),
							'value' => $row->ip_address,
						),
						array(
							'name'  => __( 'User agent', 'db-login-guard' ),
							'value' => $row->user_agent,
						),
						array(
							'name'  => __( 'Dettaglio', 'db-login-guard' ),
							'value' => $row->error_message,
						),
					),
				);
			}

			return array(
				'data' => $data,
				'done' => count( $rows ) < self::BATCH_SIZE,
			);
		}

		/**
		 * Eraser: anonimizza le righe del log riferite all'interessato.
		 *
		 * Le righe anonimizzate escono dal filtro, quindi ogni chiamata legge
		 * sempre la "prima pagina" residua (nessun OFFSET): $page non serve.
		 *
		 * @param string $email_address Email della richiesta.
		 * @param int    $page          Pagina (non usata, vedi sopra).
		 * @return array{items_removed: bool, items_retained: bool, messages: array, done: bool}
		 */
		public static function eraser_callback( $email_address, $page = 1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
			global $wpdb;

			$result = array(
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => array(),
				'done'           => true,
			);

			$ids = self::identifiers( $email_address );
			if ( empty( $ids ) ) {
				return $result;
			}

			$table = $wpdb->prefix . 'dblg_login_log';
			$where = self::where_clause( $ids );

			$args = array_merge( $ids, array( self::BATCH_SIZE ) );

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders, WordPress.DB.DirectDatabaseQuery -- $table interno, $where contiene solo placeholder.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, ip_address FROM $table WHERE $where ORDER BY id ASC LIMIT %d", $args ) );
			$rows = is_array( $rows ) ? $rows : array();

			$anonymized = 0;
			foreach ( $rows as $row ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$updated = $wpdb->update(
					$table,
					array(
						'username'   => wp_privacy_anonymize_data( 'text' ),
						'ip_address' => wp_privacy_anonymize_ip( $row->ip_address ),
						'user_agent' => '',
					),
					array( 'id' => (int) $row->id ),
					array( '%s', '%s', '%s' ),
					array( '%d' )
				);
				if ( false !== $updated ) {
					++$anonymized;
				}
			}

			if ( $anonymized > 0 ) {
				$result['items_removed'] = true;
			}

			if ( $anonymized < count( $rows ) ) {
				// Errore DB: le righe non aggiornate resterebbero nel filtro e
				// ciclerebbero all'infinito. Chiudiamo e lo segnaliamo.
				$result['items_retained'] = true;
				$result['messages'][]     = __( 'DB Login Guard: alcune righe del log accessi non sono state anonimizzate per un errore del database. Ripeti la richiesta di cancellazione.', 'db-login-guard' );
				return $result;
			}

			$result['done'] = count( $rows ) < self::BATCH_SIZE;
			return $result;
		}
	}
}
