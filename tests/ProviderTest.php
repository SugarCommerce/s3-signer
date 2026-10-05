<?php
/**
 * S3-compatible providers.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\S3Signer\AddressingStyle;
use SugarCommerce\S3Signer\Provider;

#[CoversClass( Provider::class )]
final class ProviderTest extends TestCase {

	#[DataProvider( 'endpoints' )]
	public function test_endpoints_are_built_per_provider( Provider $provider, string $region, string $expected ): void {
		$this->assertSame( $expected, $provider->endpoint( $region, account_id: 'abc123' ) );
	}

	/**
	 * @return array<string, array{0: Provider, 1: string, 2: string}>
	 */
	public static function endpoints(): array {
		return array(
			// us-east-1 keeps the legacy global hostname.
			'aws default'   => array( Provider::Aws, 'us-east-1', 's3.amazonaws.com' ),
			'aws region'    => array( Provider::Aws, 'eu-west-2', 's3.eu-west-2.amazonaws.com' ),
			'r2'            => array( Provider::R2, '', 'abc123.r2.cloudflarestorage.com' ),
			'backblaze'     => array( Provider::Backblaze, 'eu-central-003', 's3.eu-central-003.backblazeb2.com' ),
			'digitalocean'  => array( Provider::DigitalOcean, 'ams3', 'ams3.digitaloceanspaces.com' ),
			'linode'        => array( Provider::Linode, 'eu-central-1', 'eu-central-1.linodeobjects.com' ),
			'wasabi'        => array( Provider::Wasabi, 'eu-central-1', 's3.eu-central-1.wasabisys.com' ),
			'scaleway'      => array( Provider::Scaleway, 'nl-ams', 's3.nl-ams.scw.cloud' ),
		);
	}

	/**
	 * Get this wrong and every request 404s against a bucket that plainly
	 * exists.
	 */
	public function test_addressing_style_matches_the_provider(): void {
		// R2 and a self-hosted MinIO are reached by a bare host, where a
		// bucket in the hostname cannot resolve.
		$this->assertSame( AddressingStyle::Path, Provider::R2->addressing() );
		$this->assertSame( AddressingStyle::Path, Provider::MinIO->addressing() );
		$this->assertSame( AddressingStyle::Path, Provider::Other->addressing() );

		$this->assertSame( AddressingStyle::VirtualHosted, Provider::Aws->addressing() );
		$this->assertSame( AddressingStyle::VirtualHosted, Provider::Linode->addressing() );
		$this->assertSame( AddressingStyle::VirtualHosted, Provider::Wasabi->addressing() );
	}

	/**
	 * R2 rejects a signature computed for a real region.
	 */
	public function test_r2_signs_as_auto(): void {
		$this->assertSame( 'auto', Provider::R2->default_region() );
	}

	public function test_r2_needs_an_account_id(): void {
		$this->assertTrue( Provider::R2->needs_account_id() );
		$this->assertFalse( Provider::Aws->needs_account_id() );

		$this->expectException( InvalidArgumentException::class );
		$this->expectExceptionMessage( 'account id' );

		Provider::R2->endpoint();
	}

	public function test_self_hosted_providers_need_an_endpoint(): void {
		$this->assertTrue( Provider::MinIO->needs_endpoint() );
		$this->assertTrue( Provider::Other->needs_endpoint() );
		$this->assertFalse( Provider::Aws->needs_endpoint() );

		$this->assertSame( 'minio.local:9000', Provider::MinIO->endpoint( endpoint: 'minio.local:9000' ) );
		$this->assertSame( 'minio.local:9000', Provider::MinIO->endpoint( endpoint: 'https://minio.local:9000/' ) );

		$this->expectException( InvalidArgumentException::class );

		Provider::MinIO->endpoint();
	}

	public function test_an_omitted_region_falls_back_to_the_default(): void {
		$this->assertSame( 's3.us-west-1.wasabisys.com', Provider::Wasabi->endpoint() );
		$this->assertSame( 'nyc3.digitaloceanspaces.com', Provider::DigitalOcean->endpoint() );
	}

	#[DataProvider( 'signable' )]
	public function test_every_provider_produces_a_signed_url( Provider $provider ): void {
		$url = $provider
			->signer( 'AKIAEXAMPLE', 'secret-key', region: 'eu-west-2', account_id: 'abc123', endpoint: 'minio.local:9000' )
			->presign_get( 'my-bucket', 'path/file.zip', 300 );

		$this->assertStringStartsWith( 'https://', $url );
		$this->assertStringContainsString( 'X-Amz-Algorithm=AWS4-HMAC-SHA256', $url );
		$this->assertStringContainsString( 'X-Amz-Signature=', $url );
		$this->assertStringContainsString( 'path/file.zip', $url );

		// The bucket must appear exactly once, wherever the style puts it.
		$this->assertSame( 1, substr_count( $url, 'my-bucket' ), $provider->value );
	}

	/**
	 * @return array<string, array{0: Provider}>
	 */
	public static function signable(): array {
		$cases = array();

		foreach ( Provider::cases() as $provider ) {
			$cases[ $provider->value ] = array( $provider );
		}

		return $cases;
	}

	public function test_the_bucket_lands_in_the_right_place(): void {
		$virtual = Provider::Aws->signer( 'k', 's', region: 'eu-west-2' )->presign_get( 'my-bucket', 'a.zip', 60 );
		$path    = Provider::R2->signer( 'k', 's', account_id: 'abc123' )->presign_get( 'my-bucket', 'a.zip', 60 );

		$this->assertStringContainsString( 'https://my-bucket.s3.eu-west-2.amazonaws.com/a.zip', $virtual );
		$this->assertStringContainsString( 'https://abc123.r2.cloudflarestorage.com/my-bucket/a.zip', $path );
	}

	public function test_options_lists_every_provider(): void {
		$options = Provider::options();

		$this->assertCount( count( Provider::cases() ), $options );
		$this->assertSame( 'Cloudflare R2', $options['r2'] );
		$this->assertSame( 'Linode Object Storage', $options['linode'] );
	}

	/* ─── Official endpoints (1.3.0) ────────────────────────────────── */

	public function test_every_built_endpoint_is_the_provider_s_own(): void {
		foreach ( Provider::cases() as $provider ) {
			if ( $provider->needs_endpoint() ) {
				continue;
			}

			$host = $provider->endpoint( account_id: 'abcdef0123456789' );

			$this->assertTrue( $provider->is_own_endpoint( $host ), $provider->value . ': ' . $host );
		}
	}

	#[DataProvider( 'foreign_hosts' )]
	public function test_a_host_that_is_not_the_provider_s_is_refused( Provider $provider, string $host ): void {
		$this->assertFalse( $provider->is_own_endpoint( $host ) );
	}

	/**
	 * @return array<string, array{0: Provider, 1: string}>
	 */
	public static function foreign_hosts(): array {
		return array(
			'another provider'    => array( Provider::R2, 's3.amazonaws.com' ),
			'a lookalike'         => array( Provider::Aws, 's3.amazonaws.com.evil.test' ),
			'a dotted region'     => array( Provider::Backblaze, 's3.us.west.backblazeb2.com' ),
			'an address'          => array( Provider::DigitalOcean, '127.0.0.1' ),
			'minio has no host'   => array( Provider::MinIO, 'minio.example.com' ),
			'other has no host'   => array( Provider::Other, 's3.amazonaws.com' ),
			'a port smuggled in'  => array( Provider::Wasabi, 's3.eu-1.wasabisys.com:8080' ),
		);
	}
}
