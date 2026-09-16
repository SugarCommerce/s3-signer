<?php
/**
 * Bucket addressing styles.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer;

/**
 * Enum AddressingStyle
 *
 * S3-compatible providers disagree about where the bucket name belongs,
 * and the choice is not cosmetic: it changes both the `Host` header and
 * the canonical URI, so signing one way and requesting the other fails
 * with an opaque `SignatureDoesNotMatch`.
 *
 *   Path            https://endpoint/bucket/key
 *   Virtual-hosted  https://bucket.endpoint/key
 *
 * Rough state of play:
 *
 *   - **Cloudflare R2** — path-style against the account endpoint.
 *   - **AWS S3** — virtual-hosted. Path-style is deprecated for buckets
 *     created in newer regions.
 *   - **Backblaze B2** — virtual-hosted.
 *   - **DigitalOcean Spaces** — virtual-hosted (path-style also works).
 *   - **MinIO / Ceph** — path-style, typically.
 *
 * @since 1.0.0
 */
enum AddressingStyle {

	/**
	 * Bucket as the first path segment: `endpoint/bucket/key`.
	 */
	case Path;

	/**
	 * Bucket as a hostname prefix: `bucket.endpoint/key`.
	 */
	case VirtualHosted;

	/**
	 * Whether a bucket name can be safely used as a DNS label.
	 *
	 * Virtual-hosted addressing puts the bucket in the hostname, so the
	 * name has to be DNS-legal. A bucket containing a dot also breaks
	 * TLS certificate matching against a wildcard, which is why AWS has
	 * refused to create dotted buckets for virtual-hosted use for years.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket Bucket name.
	 *
	 * @return bool
	 */
	public static function is_dns_compatible( string $bucket ): bool {
		if ( strlen( $bucket ) < 3 || strlen( $bucket ) > 63 ) {
			return false;
		}

		// Lowercase alphanumeric and hyphens, not starting or ending
		// with a hyphen. Dots are excluded deliberately — see above.
		return 1 === preg_match( '/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$/', $bucket );
	}
}
