<?php
/**
 * Addressing style, provider factories, and input hardening.
 *
 * @package   Sugar\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace Sugar\S3Signer\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sugar\S3Signer\AddressingStyle;
use Sugar\S3Signer\Method;
use Sugar\S3Signer\Signer;

final class AddressingTest extends TestCase {

	private const ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
	private const SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
	private const TIMESTAMP  = 1700000000;

	/* ─── Addressing style ──────────────────────────────────────────── */

	public function test_path_style_puts_the_bucket_in_the_path(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 'storage.example.com', 'auto', self::TIMESTAMP, AddressingStyle::Path );

		$this->assertStringStartsWith(
			'https://storage.example.com/my-bucket/files/a.zip?',
			$signer->presign_get( 'my-bucket', 'files/a.zip', 60 )
		);
	}

	public function test_virtual_hosted_style_puts_the_bucket_in_the_host(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.eu-west-2.amazonaws.com', 'eu-west-2', self::TIMESTAMP, AddressingStyle::VirtualHosted );

		$this->assertStringStartsWith(
			'https://my-bucket.s3.eu-west-2.amazonaws.com/files/a.zip?',
			$signer->presign_get( 'my-bucket', 'files/a.zip', 60 )
		);
	}

	public function test_virtual_hosted_style_omits_the_bucket_from_the_path(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP, AddressingStyle::VirtualHosted );
		$url    = $signer->presign_get( 'my-bucket', 'files/a.zip', 60 );

		// The bucket must appear exactly once — in the host.
		$this->assertSame( 1, substr_count( $url, 'my-bucket' ) );
	}

	public function test_addressing_style_changes_the_signature(): void {
		$path    = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP, AddressingStyle::Path );
		$virtual = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP, AddressingStyle::VirtualHosted );

		$this->assertNotSame(
			$path->presign_get( 'my-bucket', 'k', 60 ),
			$virtual->presign_get( 'my-bucket', 'k', 60 )
		);
	}

	public function test_virtual_hosted_host_header_is_the_signed_one(): void {
		$signer  = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP, AddressingStyle::VirtualHosted );
		$request = $signer->sign_delete_object( 'my-bucket', 'k.zip' );

		$this->assertSame( 'my-bucket.s3.example.com', $request->headers['host'] );
		$this->assertSame( 'https://my-bucket.s3.example.com/k.zip', $request->url );
	}

	public function test_virtual_hosted_bucket_listing_uses_a_root_path(): void {
		$signer  = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP, AddressingStyle::VirtualHosted );
		$request = $signer->sign_list_objects( 'my-bucket', 10 );

		$this->assertStringStartsWith( 'https://my-bucket.s3.example.com/?', $request->url );
	}

	#[DataProvider( 'undnsable_buckets' )]
	public function test_virtual_hosted_rejects_buckets_that_cannot_be_dns_labels( string $bucket ): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP, AddressingStyle::VirtualHosted );

		$this->expectException( \InvalidArgumentException::class );
		$signer->presign_get( $bucket, 'k', 60 );
	}

	/** @return array<string, array{0: string}> */
	public static function undnsable_buckets(): array {
		return array(
			'uppercase'      => array( 'MyBucket' ),
			'underscore'     => array( 'my_bucket' ),
			'dotted'         => array( 'my.bucket' ),
			'too short'      => array( 'ab' ),
			'leading hyphen' => array( '-bucket' ),
			'host injection' => array( 'evil.attacker.com' ),
		);
	}

	public function test_path_style_tolerates_buckets_that_are_not_dns_labels(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP, AddressingStyle::Path );

		$this->assertStringContainsString( 'my.bucket', $signer->presign_get( 'my.bucket', 'k', 60 ) );
	}

	/* ─── Provider factories ────────────────────────────────────────── */

	public function test_r2_factory_builds_the_account_endpoint(): void {
		$url = Signer::r2( self::ACCESS_KEY, self::SECRET_KEY, 'abc123', self::TIMESTAMP )
			->presign_get( 'my-bucket', 'files/a.zip', 60 );

		$this->assertStringStartsWith( 'https://abc123.r2.cloudflarestorage.com/my-bucket/files/a.zip?', $url );
		$this->assertStringContainsString( '%2Fauto%2Fs3%2Faws4_request', $url );
	}

	public function test_r2_factory_matches_a_manually_configured_signer(): void {
		$manual = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 'abc123.r2.cloudflarestorage.com', 'auto', self::TIMESTAMP );

		$this->assertSame(
			$manual->presign_get( 'my-bucket', 'files/sample.zip', 60 ),
			Signer::r2( self::ACCESS_KEY, self::SECRET_KEY, 'abc123', self::TIMESTAMP )->presign_get( 'my-bucket', 'files/sample.zip', 60 )
		);
	}

	public function test_aws_factory_is_virtual_hosted_and_region_scoped(): void {
		$url = Signer::aws( self::ACCESS_KEY, self::SECRET_KEY, 'eu-west-2', self::TIMESTAMP )
			->presign_get( 'my-bucket', 'k.zip', 60 );

		$this->assertStringStartsWith( 'https://my-bucket.s3.eu-west-2.amazonaws.com/k.zip?', $url );
		$this->assertStringContainsString( '%2Feu-west-2%2Fs3%2F', $url );
	}

	public function test_backblaze_factory_endpoint(): void {
		$this->assertStringStartsWith(
			'https://my-bucket.s3.us-west-004.backblazeb2.com/k.zip?',
			Signer::backblaze( self::ACCESS_KEY, self::SECRET_KEY, 'us-west-004', self::TIMESTAMP )->presign_get( 'my-bucket', 'k.zip', 60 )
		);
	}

	public function test_digitalocean_factory_endpoint(): void {
		$this->assertStringStartsWith(
			'https://my-bucket.ams3.digitaloceanspaces.com/k.zip?',
			Signer::digitalocean( self::ACCESS_KEY, self::SECRET_KEY, 'ams3', self::TIMESTAMP )->presign_get( 'my-bucket', 'k.zip', 60 )
		);
	}

	public function test_minio_factory_is_path_style_and_keeps_the_port(): void {
		$this->assertStringStartsWith(
			'https://localhost:9000/my-bucket/k.zip?',
			Signer::minio( self::ACCESS_KEY, self::SECRET_KEY, 'localhost:9000', 'us-east-1', self::TIMESTAMP )->presign_get( 'my-bucket', 'k.zip', 60 )
		);
	}

	/* ─── Endpoint normalisation ────────────────────────────────────── */

	#[DataProvider( 'messy_endpoints' )]
	public function test_endpoints_are_normalised( string $input ): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, $input, 'auto', self::TIMESTAMP );

		$this->assertStringStartsWith( 'https://s3.example.com/b/k?', $signer->presign_get( 'b', 'k', 60 ) );
	}

	/** @return array<string, array{0: string}> */
	public static function messy_endpoints(): array {
		return array(
			'bare'            => array( 's3.example.com' ),
			'https scheme'    => array( 'https://s3.example.com' ),
			'http scheme'     => array( 'http://s3.example.com' ),
			'trailing slash'  => array( 'https://s3.example.com/' ),
			'with path'       => array( 'https://s3.example.com/some/path' ),
			'uppercase'       => array( 'S3.EXAMPLE.COM' ),
			'trailing dot'    => array( 's3.example.com.' ),
			'padded'          => array( '  s3.example.com  ' ),
		);
	}

	#[DataProvider( 'bad_endpoints' )]
	public function test_unusable_endpoints_are_rejected( string $input ): void {
		$this->expectException( \InvalidArgumentException::class );
		new Signer( self::ACCESS_KEY, self::SECRET_KEY, $input );
	}

	/** @return array<string, array{0: string}> */
	public static function bad_endpoints(): array {
		return array(
			'empty'     => array( '' ),
			'spaces'    => array( '   ' ),
			'newline'   => array( "s3.example.com\r\nX-Evil: 1" ),
			'space mid' => array( 's3.example .com' ),
			'scheme only' => array( 'https://' ),
		);
	}

	/* ─── Credential and region validation ──────────────────────────── */

	public function test_empty_credentials_are_rejected(): void {
		$this->expectException( \InvalidArgumentException::class );
		new Signer( '', self::SECRET_KEY, 's3.example.com' );
	}

	public function test_empty_secret_is_rejected(): void {
		$this->expectException( \InvalidArgumentException::class );
		new Signer( self::ACCESS_KEY, '  ', 's3.example.com' );
	}

	public function test_a_region_that_would_corrupt_the_scope_is_rejected(): void {
		$this->expectException( \InvalidArgumentException::class );
		new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'eu/west/2' );
	}

	/* ─── Header hardening ──────────────────────────────────────────── */

	public function test_crlf_in_a_header_value_is_rejected(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP );

		$this->expectException( \InvalidArgumentException::class );
		$signer->sign( Method::PUT, 'b', 'k', array(), 'body', array( 'content-type' => "text/plain\r\nX-Evil: yes" ) );
	}

	public function test_null_bytes_in_a_header_value_are_rejected(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP );

		$this->expectException( \InvalidArgumentException::class );
		$signer->sign( Method::PUT, 'b', 'k', array(), '', array( 'content-type' => "text/plain\x00" ) );
	}

	#[DataProvider( 'bad_header_names' )]
	public function test_invalid_header_names_are_rejected( string $name ): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP );

		$this->expectException( \InvalidArgumentException::class );
		$signer->sign( Method::PUT, 'b', 'k', array(), '', array( $name => 'value' ) );
	}

	/** @return array<string, array{0: string}> */
	public static function bad_header_names(): array {
		return array(
			'colon'   => array( 'content-type:x' ),
			'space'   => array( 'content type' ),
			'newline' => array( "x-evil\r\nx" ),
			'empty'   => array( '' ),
		);
	}

	public function test_internal_whitespace_in_header_values_is_collapsed(): void {
		$signer  = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP );
		$request = $signer->sign( Method::PUT, 'b', 'k', array(), '', array( 'content-type' => "text/plain;   charset=utf-8" ) );

		$this->assertSame( 'text/plain; charset=utf-8', $request->headers['content-type'] );
	}

	/* ─── Expiry validation ─────────────────────────────────────────── */

	public function test_expiry_beyond_the_sigv4_maximum_is_rejected(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP );

		$this->expectException( \InvalidArgumentException::class );
		$signer->presign_get( 'b', 'k', Signer::MAX_EXPIRES + 1 );
	}

	public function test_the_sigv4_maximum_itself_is_accepted(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP );

		$this->assertStringContainsString( 'X-Amz-Expires=604800', $signer->presign_get( 'b', 'k', Signer::MAX_EXPIRES ) );
	}

	public function test_a_non_positive_expiry_is_rejected(): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.example.com', 'auto', self::TIMESTAMP );

		$this->expectException( \InvalidArgumentException::class );
		$signer->presign_get( 'b', 'k', 0 );
	}
}
