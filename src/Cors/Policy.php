<?php
/**
 * A bucket's whole CORS configuration.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.1.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer\Cors;

/**
 * Class Policy
 *
 * An ordered set of rules, with the XML on both sides of the wire and the
 * questions worth asking of it.
 *
 * The questions are the reason this is a class rather than an array. "Is CORS
 * configured?" is not a useful thing to know — a bucket can have three rules
 * and still refuse the upload you are about to attempt. What a deployment
 * check actually wants to ask is whether *this* origin may perform *this*
 * operation, which is what supports_multipart_upload() answers.
 *
 * @since 1.1.0
 */
final readonly class Policy implements \Countable, \IteratorAggregate {

	/**
	 * Most providers cap a bucket at 100 rules.
	 */
	public const MAX_RULES = 100;

	/**
	 * @param array<int, Rule> $rules The rules, in the order S3 evaluates them.
	 *
	 * @throws \InvalidArgumentException Above MAX_RULES.
	 */
	public function __construct( public array $rules = array() ) {
		if ( count( $rules ) > self::MAX_RULES ) {
			throw new \InvalidArgumentException(
				sprintf( 'A bucket takes at most %d CORS rules.', self::MAX_RULES )
			);
		}
	}

	/**
	 * The policy a direct-to-storage uploader needs.
	 *
	 * Upload is pinned to the origins that serve the uploader; reading stays
	 * open, because a presigned download link is a credential in itself and
	 * restricting which page may follow it protects nothing.
	 *
	 * @since 1.1.0
	 *
	 * @param array<int, string> $origins Origins the uploader is served from.
	 *
	 * @return self
	 */
	public static function for_browser_uploads( array $origins ): self {
		return new self( array(
			Rule::browser_upload( $origins ),
			Rule::browser_read(),
		) );
	}

	/**
	 * Parse a GetBucketCors response.
	 *
	 * @since 1.1.0
	 *
	 * @param string $xml Response body. An empty body — which is what a
	 *                    bucket with no configuration returns — gives an
	 *                    empty policy rather than an error.
	 *
	 * @return self
	 *
	 * @throws \RuntimeException When the body is not parseable XML.
	 */
	public static function from_xml( string $xml ): self {
		$xml = trim( $xml );

		if ( '' === $xml ) {
			return new self();
		}

		$previous = libxml_use_internal_errors( true );
		$document = simplexml_load_string( $xml );
		libxml_clear_errors();
		libxml_use_internal_errors( $previous );

		if ( false === $document ) {
			throw new \RuntimeException( 'Could not parse the CORS configuration.' );
		}

		$rules = array();

		foreach ( $document->CORSRule as $node ) {
			$rules[] = Rule::from_array( array(
				'ID'             => (string) $node->ID,
				'AllowedOrigins' => self::strings( $node->AllowedOrigin ),
				'AllowedMethods' => self::strings( $node->AllowedMethod ),
				'AllowedHeaders' => self::strings( $node->AllowedHeader ),
				'ExposeHeaders'  => self::strings( $node->ExposeHeader ),
				'MaxAgeSeconds'  => (int) $node->MaxAgeSeconds,
			) );
		}

		return new self( $rules );
	}

	/**
	 * The policy as a PutBucketCors body.
	 *
	 * @since 1.1.0
	 *
	 * @return string XML.
	 */
	public function to_xml(): string {
		$xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
			. '<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' . "\n";

		foreach ( $this->rules as $rule ) {
			$xml .= '  <CORSRule>' . "\n";

			if ( '' !== $rule->id ) {
				$xml .= self::element( 'ID', $rule->id );
			}

			foreach ( $rule->origins as $origin ) {
				$xml .= self::element( 'AllowedOrigin', $origin );
			}

			foreach ( $rule->methods as $method ) {
				$xml .= self::element( 'AllowedMethod', $method );
			}

			foreach ( $rule->headers as $header ) {
				$xml .= self::element( 'AllowedHeader', $header );
			}

			foreach ( $rule->expose as $header ) {
				$xml .= self::element( 'ExposeHeader', $header );
			}

			if ( $rule->max_age > 0 ) {
				$xml .= self::element( 'MaxAgeSeconds', (string) $rule->max_age );
			}

			$xml .= '  </CORSRule>' . "\n";
		}

		return $xml . '</CORSConfiguration>' . "\n";
	}

	/**
	 * May this origin use this method?
	 *
	 * @since 1.1.0
	 *
	 * @param string $origin Scheme and host.
	 * @param string $method HTTP method.
	 *
	 * @return bool
	 */
	public function allows( string $origin, string $method ): bool {
		foreach ( $this->rules as $rule ) {
			if ( $rule->allows( $origin, $method ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * May this origin read this response header, for this method?
	 *
	 * The method matters. Exposing ETag on a rule that only allows GET does
	 * nothing for an upload, and a check that ignored the method would call
	 * that configuration good.
	 *
	 * @since 1.1.0
	 *
	 * @param string $origin Scheme and host.
	 * @param string $method HTTP method.
	 * @param string $header Response header name.
	 *
	 * @return bool
	 */
	public function exposes( string $origin, string $method, string $header ): bool {
		foreach ( $this->rules as $rule ) {
			if ( $rule->allows( $origin, $method ) && $rule->exposes( $header ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Will a browser multipart upload from this origin actually work?
	 *
	 * The question a deployment check should ask, rather than "is CORS set?".
	 * Both halves have to hold: the browser must be allowed to PUT, and it
	 * must be allowed to read back the ETag of what it PUT. A policy with the
	 * first and not the second lets every part upload and then fails at
	 * assembly, with an error that mentions neither CORS nor ETag.
	 *
	 * @since 1.1.0
	 *
	 * @param string $origin Origin the uploader is served from.
	 *
	 * @return array{ok: bool, reason: string} A reason when it will not.
	 */
	public function supports_multipart_upload( string $origin ): array {
		if ( ! $this->rules ) {
			return array( 'ok' => false, 'reason' => 'The bucket has no CORS configuration.' );
		}

		if ( ! $this->allows( $origin, 'PUT' ) ) {
			return array(
				'ok'     => false,
				'reason' => sprintf( 'No rule allows PUT from %s.', $origin ),
			);
		}

		if ( ! $this->exposes( $origin, 'PUT', 'ETag' ) ) {
			return array(
				'ok'     => false,
				'reason' => 'PUT is allowed but ETag is not exposed, so parts upload and '
					. 'the upload then fails at assembly.',
			);
		}

		return array( 'ok' => true, 'reason' => '' );
	}

	/**
	 * Every origin any rule allows.
	 *
	 * @since 1.1.0
	 *
	 * @return array<int, string>
	 */
	public function origins(): array {
		return $this->unique( static fn( Rule $rule ): array => $rule->origins );
	}

	/**
	 * Every method any rule allows.
	 *
	 * @since 1.1.0
	 *
	 * @return array<int, string>
	 */
	public function methods(): array {
		return $this->unique( static fn( Rule $rule ): array => $rule->methods );
	}

	/**
	 * How many rules.
	 *
	 * @since 1.1.0
	 *
	 * @return int
	 */
	public function count(): int {
		return count( $this->rules );
	}

	/**
	 * Iterate the rules.
	 *
	 * @since 1.1.0
	 *
	 * @return \ArrayIterator<int, Rule>
	 */
	public function getIterator(): \ArrayIterator {
		return new \ArrayIterator( $this->rules );
	}

	/**
	 * Collect one field across every rule, without duplicates.
	 *
	 * @since 1.1.0
	 *
	 * @param callable $field Returns the field's values for one rule.
	 *
	 * @return array<int, string>
	 */
	private function unique( callable $field ): array {
		$values = array();

		foreach ( $this->rules as $rule ) {
			$values = array_merge( $values, $field( $rule ) );
		}

		return array_values( array_unique( $values ) );
	}

	/**
	 * One escaped XML element.
	 *
	 * @since 1.1.0
	 *
	 * @param string $name  Element name.
	 * @param string $value Text content.
	 *
	 * @return string
	 */
	private static function element( string $name, string $value ): string {
		return '    <' . $name . '>'
			. htmlspecialchars( $value, ENT_XML1 | ENT_COMPAT, 'UTF-8' )
			. '</' . $name . '>' . "\n";
	}

	/**
	 * A repeated XML element as a list of strings.
	 *
	 * @since 1.1.0
	 *
	 * @param \SimpleXMLElement|null $nodes The repeated element.
	 *
	 * @return array<int, string>
	 */
	private static function strings( ?\SimpleXMLElement $nodes ): array {
		$values = array();

		foreach ( $nodes ?? array() as $node ) {
			$values[] = (string) $node;
		}

		return $values;
	}
}
