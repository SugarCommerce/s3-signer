<?php
/**
 * HTTP methods valid in an S3 canonical request.
 *
 * @package   Sugar\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace Sugar\S3Signer;

/**
 * Enum Method
 *
 * The HTTP verb is the first line of every SigV4 canonical request, so a
 * typo silently produces a valid-looking signature that the storage
 * provider rejects with an opaque 403. An enum makes that class of bug
 * impossible.
 *
 * @since 1.0.0
 */
enum Method: string {

	case GET    = 'GET';
	case PUT    = 'PUT';
	case POST   = 'POST';
	case DELETE = 'DELETE';
	case HEAD   = 'HEAD';

	/**
	 * Whether this method normally carries a request body.
	 *
	 * Used to decide whether an empty-payload hash is expected. Purely
	 * informational — signing never depends on it.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function has_body(): bool {
		return $this === self::PUT || $this === self::POST;
	}
}
