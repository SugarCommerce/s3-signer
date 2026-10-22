<?php
/**
 * S3-compatible storage providers.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer;

/**
 * Enum Provider
 *
 * The providers people actually use, and what each needs to build an
 * endpoint. This exists so an application can offer a dropdown rather
 * than asking an operator to type a hostname they will get wrong.
 *
 * Three things vary and all three break silently when guessed:
 *
 *   - **Endpoint shape.** Some interpolate a region, R2 interpolates an
 *     account id, MinIO is whatever the operator hosts.
 *   - **Addressing style.** Virtual-hosted puts the bucket in the
 *     hostname, path style puts it in the path. Get it wrong and every
 *     request 404s against a bucket that plainly exists.
 *   - **Region.** R2 signs everything as `auto`; AWS rejects a signature
 *     computed for the wrong region.
 *
 * @since 1.0.0
 */
enum Provider: string {

	/**
	 * Amazon S3: `s3.<region>.amazonaws.com`, virtual-hosted.
	 */
	case Aws = 'aws';

	/**
	 * Cloudflare R2: `<account id>.r2.cloudflarestorage.com`, path-style.
	 */
	case R2 = 'r2';

	/**
	 * Backblaze B2: `s3.<region>.backblazeb2.com`, virtual-hosted.
	 */
	case Backblaze = 'backblaze';

	/**
	 * DigitalOcean Spaces: `<region>.digitaloceanspaces.com`, virtual-hosted.
	 */
	case DigitalOcean = 'digitalocean';

	/**
	 * Linode (Akamai) Object Storage: `<region>.linodeobjects.com`.
	 */
	case Linode = 'linode';

	/**
	 * Wasabi: `s3.<region>.wasabisys.com`, virtual-hosted.
	 */
	case Wasabi = 'wasabi';

	/**
	 * Scaleway Object Storage: `s3.<region>.scw.cloud`, virtual-hosted.
	 */
	case Scaleway = 'scaleway';

	/**
	 * Self-hosted MinIO or Ceph: a host the operator types, path-style.
	 */
	case MinIO = 'minio';

	/**
	 * Anything else speaking S3: a host the operator types, path-style.
	 */
	case Other = 'other';

	/**
	 * A human label, for a settings dropdown.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function label(): string {
		return match ( $this ) {
			self::Aws          => 'Amazon S3',
			self::R2           => 'Cloudflare R2',
			self::Backblaze    => 'Backblaze B2',
			self::DigitalOcean => 'DigitalOcean Spaces',
			self::Linode       => 'Linode Object Storage',
			self::Wasabi       => 'Wasabi',
			self::Scaleway     => 'Scaleway Object Storage',
			self::MinIO        => 'MinIO (self-hosted)',
			self::Other        => 'Other S3-compatible',
		};
	}

	/**
	 * Whether this provider identifies the endpoint by account id rather
	 * than region. Only R2 does; the setting is meaningless elsewhere and
	 * a form should hide it.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function needs_account_id(): bool {
		return self::R2 === $this;
	}

	/**
	 * Whether the operator must supply the endpoint themselves.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function needs_endpoint(): bool {
		return self::MinIO === $this || self::Other === $this;
	}

	/**
	 * The region to sign with when the operator gives none.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function default_region(): string {
		return match ( $this ) {
			// R2 signs everything as `auto`; a real region is rejected.
			self::R2                  => 'auto',
			self::Aws                 => 'us-east-1',
			self::DigitalOcean        => 'nyc3',
			self::Linode              => 'us-east-1',
			self::Backblaze, self::Wasabi => 'us-west-1',
			self::Scaleway            => 'fr-par',
			self::MinIO, self::Other  => 'us-east-1',
		};
	}

	/**
	 * Where the bucket goes in the URL.
	 *
	 * @since 1.0.0
	 *
	 * @return AddressingStyle
	 */
	public function addressing(): AddressingStyle {
		return match ( $this ) {
			// A self-hosted MinIO is usually reached by IP or a bare
			// hostname, where a bucket in the hostname cannot resolve.
			self::R2, self::MinIO, self::Other => AddressingStyle::Path,
			default                            => AddressingStyle::VirtualHosted,
		};
	}

	/**
	 * Build the endpoint host for this provider.
	 *
	 * @since 1.0.0
	 *
	 * @param string $region     Region name.
	 * @param string $account_id Account id — R2 only.
	 * @param string $endpoint   Explicit host, for MinIO and Other.
	 *
	 * @return string Host only, no scheme.
	 *
	 * @throws \InvalidArgumentException When a required part is missing, or
	 *                                   a region or account id is not a plain
	 *                                   label.
	 */
	public function endpoint( string $region = '', string $account_id = '', string $endpoint = '' ): string {
		$region = '' !== trim( $region ) ? trim( $region ) : $this->default_region();

		if ( $this->needs_endpoint() ) {
			$host = preg_replace( '#^https?://#i', '', trim( $endpoint ) );
			$host = rtrim( (string) $host, '/' );

			if ( '' === $host ) {
				throw new \InvalidArgumentException( $this->label() . ' needs an endpoint host.' );
			}

			return $host;
		}

		// The account id and the region are spliced into a hostname, so each
		// has to be one DNS label. A region of `evil.example/` would make the
		// host `s3.evil.example/.amazonaws.com`, which everything downstream
		// reads as `s3.evil.example`.
		if ( self::R2 === $this ) {
			if ( '' === trim( $account_id ) ) {
				throw new \InvalidArgumentException( 'Cloudflare R2 needs an account id.' );
			}

			if ( ! self::is_label( trim( $account_id ) ) ) {
				throw new \InvalidArgumentException( 'An account id is letters, digits and hyphens only.' );
			}

			return trim( $account_id ) . '.r2.cloudflarestorage.com';
		}

		if ( ! self::is_label( $region ) ) {
			throw new \InvalidArgumentException( 'A region is letters, digits and hyphens only.' );
		}

		return match ( $this ) {
			self::Aws          => 'us-east-1' === $region ? 's3.amazonaws.com' : 's3.' . $region . '.amazonaws.com',
			self::Backblaze    => 's3.' . $region . '.backblazeb2.com',
			self::DigitalOcean => $region . '.digitaloceanspaces.com',
			self::Linode       => $region . '.linodeobjects.com',
			self::Wasabi       => 's3.' . $region . '.wasabisys.com',
			self::Scaleway     => 's3.' . $region . '.scw.cloud',
			default            => throw new \InvalidArgumentException( 'Unhandled provider: ' . $this->value ),
		};
	}

	/**
	 * A configured signer for this provider.
	 *
	 * @since 1.0.0
	 *
	 * @param string $access_key Access key id.
	 * @param string $secret_key Secret access key.
	 * @param string $region     Region name.
	 * @param string $account_id Account id — R2 only.
	 * @param string $endpoint   Explicit host — MinIO and Other only.
	 *
	 * @return Signer
	 *
	 * @throws \InvalidArgumentException As endpoint() and the Signer
	 *                                   constructor do.
	 */
	public function signer(
		#[\SensitiveParameter] string $access_key,
		#[\SensitiveParameter] string $secret_key,
		string $region = '',
		string $account_id = '',
		string $endpoint = ''
	): Signer {
		return new Signer(
			$access_key,
			$secret_key,
			$this->endpoint( $region, $account_id, $endpoint ),
			'' !== trim( $region ) ? trim( $region ) : $this->default_region(),
			null,
			$this->addressing()
		);
	}

	/**
	 * Whether a host is this provider's own endpoint.
	 *
	 * The check for an application that connects to buckets other people
	 * chose. Their requests go to the endpoint host, so a host they could
	 * steer is one they control — pointed at your own network, or at a
	 * server that shows your scanner one file and their buyers another. A
	 * host built by endpoint() from a region and account id that are plain
	 * labels is the provider's, and this says so whatever endpoint() does
	 * with an edge case. MinIO and Other have no official host, so nothing
	 * passes for them.
	 *
	 * @since 1.3.0
	 *
	 * @param string $host Host, no scheme or port.
	 *
	 * @return bool
	 */
	public function is_own_endpoint( string $host ): bool {
		$pattern = match ( $this ) {
			self::R2           => '/^[a-z0-9]{8,64}\.r2\.cloudflarestorage\.com$/',
			self::Aws          => '/^s3(\.[a-z0-9-]+)?\.amazonaws\.com$/',
			self::Backblaze    => '/^s3\.[a-z0-9-]+\.backblazeb2\.com$/',
			self::DigitalOcean => '/^[a-z0-9-]+\.digitaloceanspaces\.com$/',
			self::Linode       => '/^[a-z0-9-]+\.linodeobjects\.com$/',
			self::Wasabi       => '/^s3\.[a-z0-9-]+\.wasabisys\.com$/',
			self::Scaleway     => '/^s3\.[a-z0-9-]+\.scw\.cloud$/',
			self::MinIO, self::Other => null,
		};

		return null !== $pattern && 1 === preg_match( $pattern, $host );
	}

	/**
	 * Whether a value is a single DNS label: letters, digits and hyphens,
	 * 1 to 63 of them.
	 *
	 * @since 1.4.0
	 *
	 * @param string $value Region or account id.
	 *
	 * @return bool
	 */
	public static function is_label( string $value ): bool {
		return 1 === preg_match( '/^[A-Za-z0-9\-]{1,63}$/', $value );
	}

	/**
	 * Every provider as `value => label`, for a settings dropdown.
	 *
	 * @since 1.0.0
	 *
	 * @return array<string, string>
	 */
	public static function options(): array {
		$options = array();

		foreach ( self::cases() as $case ) {
			$options[ $case->value ] = $case->label();
		}

		return $options;
	}
}
