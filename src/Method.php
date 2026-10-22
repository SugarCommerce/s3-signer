<?php
/**
 * HTTP methods valid in an S3 canonical request.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer;

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

	/**
	 * Read an object or a bucket listing.
	 */
	case GET = 'GET';

	/**
	 * Create or replace an object, a part, or a bucket setting.
	 */
	case PUT = 'PUT';

	/**
	 * Start or complete a multipart upload.
	 */
	case POST = 'POST';

	/**
	 * Remove an object or a bucket setting, or abort an upload.
	 */
	case DELETE = 'DELETE';

	/**
	 * Read an object's metadata without its body.
	 */
	case HEAD = 'HEAD';

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
