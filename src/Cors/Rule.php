<?php
/**
 * One bucket CORS rule.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.1.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer\Cors;

/**
 * Class Rule
 *
 * A bucket's CORS configuration is the setting that decides whether a browser
 * may talk to storage directly, and it is the one people get wrong — usually
 * not by leaving it off, which fails loudly, but by writing a rule that looks
 * complete and is missing one line.
 *
 * The named constructors below are the shapes worth having. Prefer them to
 * assembling a rule by hand: browser_upload() in particular exists because the
 * obvious hand-written version of it is broken. See exposes() for why.
 *
 * @since 1.1.0
 */
final readonly class Rule {

	/**
	 * Methods S3 accepts in a CORS rule.
	 */
	public const METHODS = array( 'GET', 'PUT', 'POST', 'DELETE', 'HEAD' );

	/**
	 * Headers worth exposing for a readable object.
	 *
	 * Without these on the rule the browser hides them from `fetch()` even
	 * though the response carries them.
	 */
	public const READ_HEADERS = array( 'Content-Length', 'Content-Type', 'ETag', 'Last-Modified' );

	/**
	 * @param array<int, string> $origins Origins the rule allows. `*` matches
	 *                                    everything; S3 does no subdomain
	 *                                    matching, so `*.example.com` matches
	 *                                    nothing at all.
	 * @param array<int, string> $methods Methods the rule allows.
	 * @param array<int, string> $headers Request headers the browser may send.
	 * @param array<int, string> $expose  Response headers the browser may read.
	 * @param int                $max_age How long a preflight may be cached.
	 * @param string             $id      Rule name, for reading a config back.
	 *
	 * @throws \InvalidArgumentException On no origins, no methods, or a method
	 *                                   S3 will reject.
	 */
	public function __construct(
		public array $origins,
		public array $methods,
		public array $headers = array( '*' ),
		public array $expose = array(),
		public int $max_age = 3600,
		public string $id = '',
	) {
		if ( ! $origins ) {
			throw new \InvalidArgumentException( 'A CORS rule needs at least one origin.' );
		}

		if ( ! $methods ) {
			throw new \InvalidArgumentException( 'A CORS rule needs at least one method.' );
		}

		foreach ( $methods as $method ) {
			if ( ! in_array( $method, self::METHODS, true ) ) {
				throw new \InvalidArgumentException(
					sprintf( 'Not a method S3 accepts in a CORS rule: %s.', $method )
				);
			}
		}
	}

	/**
	 * A rule for uploading from the browser.
	 *
	 * ETag is exposed, and that is the entire point of this constructor.
	 * A multipart upload works like this: the browser PUTs each part, storage
	 * answers with that part's ETag, and the browser sends every ETag back to
	 * assemble the object. If the rule does not expose ETag, every part
	 * uploads successfully, the browser cannot read a single one of them, and
	 * the upload fails at the last step with an error that says nothing about
	 * CORS. It is a slow afternoon to diagnose and one line to prevent.
	 *
	 * @since 1.1.0
	 *
	 * @param array<int, string> $origins Origins the uploader is served from.
	 * @param int                $max_age Preflight cache lifetime.
	 *
	 * @return self
	 */
	public static function browser_upload( array $origins, int $max_age = 3600 ): self {
		return new self(
			origins: $origins,
			methods: array( 'PUT', 'POST' ),
			headers: array( '*' ),
			expose: array( 'ETag' ),
			max_age: $max_age,
			id: 'BrowserUpload',
		);
	}

	/**
	 * A rule for reading objects from the browser.
	 *
	 * @since 1.1.0
	 *
	 * @param array<int, string> $origins Origins that may read.
	 * @param int                $max_age Preflight cache lifetime.
	 *
	 * @return self
	 */
	public static function browser_read( array $origins = array( '*' ), int $max_age = 86_400 ): self {
		return new self(
			origins: $origins,
			methods: array( 'GET', 'HEAD' ),
			headers: array( 'Range' ),
			expose: self::READ_HEADERS,
			max_age: $max_age,
			id: 'BrowserRead',
		);
	}

	/**
	 * Rebuild a rule from its array form.
	 *
	 * @since 1.1.0
	 *
	 * @param array $rule As produced by to_array(), or parsed from XML.
	 *
	 * @return self
	 */
	public static function from_array( array $rule ): self {
		return new self(
			origins: array_values( (array) ( $rule['AllowedOrigins'] ?? array() ) ),
			methods: array_values( (array) ( $rule['AllowedMethods'] ?? array() ) ),
			headers: array_values( (array) ( $rule['AllowedHeaders'] ?? array() ) ),
			expose: array_values( (array) ( $rule['ExposeHeaders'] ?? array() ) ),
			max_age: (int) ( $rule['MaxAgeSeconds'] ?? 0 ),
			id: (string) ( $rule['ID'] ?? '' ),
		);
	}

	/**
	 * Does this rule cover an origin?
	 *
	 * @since 1.1.0
	 *
	 * @param string $origin Scheme and host, e.g. `https://example.com`.
	 *
	 * @return bool
	 */
	public function covers( string $origin ): bool {
		return in_array( '*', $this->origins, true ) || in_array( $origin, $this->origins, true );
	}

	/**
	 * Does this rule allow a method from an origin?
	 *
	 * @since 1.1.0
	 *
	 * @param string $origin Origin to test.
	 * @param string $method HTTP method.
	 *
	 * @return bool
	 */
	public function allows( string $origin, string $method ): bool {
		return $this->covers( $origin ) && in_array( strtoupper( $method ), $this->methods, true );
	}

	/**
	 * Does this rule let the browser read a response header?
	 *
	 * Unlike allowed headers, there is no wildcard here that every provider
	 * honours — S3 accepts `*` in ExposeHeaders, R2 historically did not, and
	 * a rule that relies on it works in testing and fails in production. Name
	 * the headers.
	 *
	 * @since 1.1.0
	 *
	 * @param string $header Response header name, any case.
	 *
	 * @return bool
	 */
	public function exposes( string $header ): bool {
		foreach ( $this->expose as $exposed ) {
			if ( 0 === strcasecmp( $exposed, $header ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The rule as S3 names its fields.
	 *
	 * @since 1.1.0
	 *
	 * @return array<string, mixed>
	 */
	public function to_array(): array {
		$rule = array(
			'AllowedOrigins' => $this->origins,
			'AllowedMethods' => $this->methods,
		);

		if ( $this->headers ) {
			$rule['AllowedHeaders'] = $this->headers;
		}

		if ( $this->expose ) {
			$rule['ExposeHeaders'] = $this->expose;
		}

		if ( $this->max_age > 0 ) {
			$rule['MaxAgeSeconds'] = $this->max_age;
		}

		if ( '' !== $this->id ) {
			$rule['ID'] = $this->id;
		}

		return $rule;
	}
}
