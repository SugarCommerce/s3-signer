<?php
/**
 * The result of signing a request with SigV4 header authentication.
 *
 * @package   Sugar\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace Sugar\S3Signer;

/**
 * Class SignedRequest
 *
 * An immutable description of a request that is ready to send: the URL,
 * the verb, and every header the signature covers. This library performs
 * no I/O — you hand this object to cURL, Guzzle, `wp_remote_request()`,
 * or anything else.
 *
 * The headers are already complete. Do not add, remove, or reorder any
 * of them before sending: the signature is computed over exactly this
 * set, so a single extra `x-amz-*` header invalidates it.
 *
 * Typical use:
 *
 *   $req = $signer->sign_delete_object( 'my-bucket', 'path/file.zip' );
 *
 *   $ch = curl_init( $req->url );
 *   curl_setopt_array( $ch, [
 *       CURLOPT_CUSTOMREQUEST  => $req->method->value,
 *       CURLOPT_HTTPHEADER     => $req->curl_headers(),
 *       CURLOPT_RETURNTRANSFER => true,
 *   ] );
 *
 * @since 1.0.0
 */
final readonly class SignedRequest {

	/**
	 * Build the signed request.
	 *
	 * @since 1.0.0
	 *
	 * @param Method                $method  HTTP verb the signature covers.
	 * @param string                $url     Fully-qualified HTTPS URL including query string.
	 * @param array<string, string> $headers Complete header set, keyed by header name.
	 * @param string                $body    Raw request body ('' for bodyless verbs).
	 */
	public function __construct(
		public Method $method,
		public string $url,
		public array $headers,
		public string $body = '',
	) {}

	/**
	 * Headers as a cURL-shaped list of "Name: value" strings.
	 *
	 * @since 1.0.0
	 *
	 * @return string[]
	 */
	public function curl_headers(): array {
		$out = array();

		foreach ( $this->headers as $name => $value ) {
			$out[] = $name . ': ' . $value;
		}

		return $out;
	}

	/**
	 * Look up a single header, case-insensitively.
	 *
	 * @since 1.0.0
	 *
	 * @param string $name Header name.
	 *
	 * @return string|null Value, or null when the header is not present.
	 */
	public function header( string $name ): ?string {
		foreach ( $this->headers as $key => $value ) {
			if ( 0 === strcasecmp( $key, $name ) ) {
				return $value;
			}
		}

		return null;
	}
}
