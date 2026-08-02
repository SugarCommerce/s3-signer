<?php
/**
 * Signer test suite.
 *
 * The golden signatures below were produced by this library and verified
 * byte-for-byte against the signer that has been serving Cloudflare R2
 * downloads in production. Treat any change to them as a breaking change:
 * a differing signature means every presigned URL stops working.
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
use Sugar\S3Signer\ContentDisposition;
use Sugar\S3Signer\Method;
use Sugar\S3Signer\Signer;

final class SignerTest extends TestCase {

	/** Public AWS documentation example credentials — not live. */
	private const ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
	private const SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
	private const ENDPOINT   = 'abc123.r2.cloudflarestorage.com';

	/** 2023-11-14T22:13:20Z — frozen so signatures are reproducible. */
	private const TIMESTAMP = 1700000000;
	private const AMZ_DATE  = '20231114T221320Z';
	private const SCOPE     = '20231114/auto/s3/aws4_request';

	private function signer( ?int $timestamp = self::TIMESTAMP, string $region = 'auto' ): Signer {
		return new Signer( self::ACCESS_KEY, self::SECRET_KEY, self::ENDPOINT, $region, $timestamp );
	}

	/* ─── Golden vectors ────────────────────────────────────────────── */

	public function test_presign_get_matches_golden_vector(): void {
		$this->assertSame(
			'https://abc123.r2.cloudflarestorage.com/my-bucket/files/sample.zip'
			. '?X-Amz-Algorithm=AWS4-HMAC-SHA256'
			. '&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20231114%2Fauto%2Fs3%2Faws4_request'
			. '&X-Amz-Date=20231114T221320Z'
			. '&X-Amz-Expires=60'
			. '&X-Amz-SignedHeaders=host'
			. '&X-Amz-Signature=8ca5778a283c845b6dcefb642cdd8fa3bb2a32b81c5253837656e22651b53c19',
			$this->signer()->presign_get( 'my-bucket', 'files/sample.zip', 60 )
		);
	}

	public function test_presign_put_matches_golden_vector(): void {
		$this->assertStringEndsWith(
			'X-Amz-Signature=622471e7c3eb8e1aa2c1f0034e966e26702b6a0576bfe2048367825e897a4ffe',
			$this->signer()->presign_put( 'my-bucket', 'files/new.zip', 3600 )
		);
	}

	public function test_presign_upload_part_matches_golden_vector(): void {
		$url = $this->signer()->presign_upload_part( 'my-bucket', 'big/file.zip', 'UP-123', 7, 900 );

		$this->assertStringContainsString( 'partNumber=7', $url );
		$this->assertStringContainsString( 'uploadId=UP-123', $url );
		$this->assertStringEndsWith(
			'X-Amz-Signature=a3787dcca934313c32e64005245eeae0a588ba1957859dd8c7d60a744de7ac53',
			$url
		);
	}

	public function test_sign_delete_object_matches_golden_vector(): void {
		$request = $this->signer()->sign_delete_object( 'my-bucket', 'files/sample.zip' );

		$this->assertSame(
			'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/' . self::SCOPE
			. ', SignedHeaders=host;x-amz-content-sha256;x-amz-date'
			. ', Signature=09962d0dd3db84f7a281daa1a17177bd9d1ef7596d935ef4109370a48543f3b0',
			$request->headers['Authorization']
		);
		$this->assertSame( 'https://abc123.r2.cloudflarestorage.com/my-bucket/files/sample.zip', $request->url );
	}

	public function test_sign_put_object_matches_golden_vector(): void {
		$request = $this->signer()->sign_put_object( 'my-bucket', 'files/x.txt', 'hello world', 'text/plain' );

		$this->assertStringEndsWith(
			'Signature=a8845544d8b0320e683868c6aac840dc57be2b68fb8f91d7d2d7b4dab3434257',
			$request->headers['Authorization']
		);
	}

	public function test_sign_list_objects_matches_golden_vector(): void {
		$request = $this->signer()->sign_list_objects( 'my-bucket', 100, 'files/', '/', '' );

		$this->assertSame(
			'https://abc123.r2.cloudflarestorage.com/my-bucket'
			. '?delimiter=%2F&list-type=2&max-keys=100&prefix=files%2F',
			$request->url
		);
		$this->assertStringEndsWith(
			'Signature=d816c4aedf821364b0710198fb0fb8ac7a012fe5aa473f4e070188234d8a6bbd',
			$request->headers['Authorization']
		);
	}

	/* ─── Payload hashing ───────────────────────────────────────────── */

	public function test_body_is_hashed_into_the_content_sha_header(): void {
		$request = $this->signer()->sign_put_object( 'my-bucket', 'k.txt', 'hello world' );

		// Well-known SHA-256 of "hello world".
		$this->assertSame(
			'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
			$request->headers['x-amz-content-sha256']
		);
	}

	public function test_bodyless_requests_hash_the_empty_string(): void {
		$request = $this->signer()->sign_delete_object( 'my-bucket', 'k.txt' );

		// Well-known SHA-256 of "".
		$this->assertSame(
			'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			$request->headers['x-amz-content-sha256']
		);
	}

	/* ─── Determinism and key sensitivity ───────────────────────────── */

	public function test_signing_is_deterministic_for_a_fixed_clock(): void {
		$this->assertSame(
			$this->signer()->presign_get( 'b', 'k', 60 ),
			$this->signer()->presign_get( 'b', 'k', 60 )
		);
	}

	public function test_a_different_secret_produces_a_different_signature(): void {
		$other = new Signer( self::ACCESS_KEY, 'a-different-secret', self::ENDPOINT, 'auto', self::TIMESTAMP );

		$this->assertNotSame(
			$this->signer()->presign_get( 'b', 'k', 60 ),
			$other->presign_get( 'b', 'k', 60 )
		);
	}

	public function test_a_different_region_produces_a_different_signature(): void {
		$this->assertNotSame(
			$this->signer( region: 'auto' )->presign_get( 'b', 'k', 60 ),
			$this->signer( region: 'eu-west-2' )->presign_get( 'b', 'k', 60 )
		);
	}

	/**
	 * @param array{0: string, 1: string, 2: int} $a
	 * @param array{0: string, 1: string, 2: int} $b
	 */
	#[DataProvider( 'varying_inputs' )]
	public function test_varying_any_signed_input_changes_the_signature( array $a, array $b ): void {
		$signer = $this->signer();

		$this->assertNotSame(
			$signer->presign_get( $a[0], $a[1], $a[2] ),
			$signer->presign_get( $b[0], $b[1], $b[2] )
		);
	}

	/** @return array<string, array{0: array{0:string,1:string,2:int}, 1: array{0:string,1:string,2:int}}> */
	public static function varying_inputs(): array {
		return array(
			'bucket'  => array( array( 'bucket-a', 'k', 60 ), array( 'bucket-b', 'k', 60 ) ),
			'key'     => array( array( 'b', 'key-a', 60 ), array( 'b', 'key-b', 60 ) ),
			'expiry'  => array( array( 'b', 'k', 60 ), array( 'b', 'k', 61 ) ),
		);
	}

	public function test_the_wall_clock_is_used_when_no_timestamp_is_given(): void {
		$url = $this->signer( timestamp: null )->presign_get( 'b', 'k', 60 );

		$this->assertMatchesRegularExpression( '/X-Amz-Date=\d{8}T\d{6}Z/', $url );
		$this->assertStringNotContainsString( self::AMZ_DATE, $url );
	}

	/* ─── Key and query encoding ────────────────────────────────────── */

	public function test_key_hierarchy_survives_encoding(): void {
		$this->assertStringContainsString(
			'/my-bucket/a/b/c/file.zip?',
			$this->signer()->presign_get( 'my-bucket', 'a/b/c/file.zip', 60 )
		);
	}

	public function test_a_leading_slash_on_the_key_is_ignored(): void {
		$this->assertSame(
			$this->signer()->presign_get( 'b', 'a/file.zip', 60 ),
			$this->signer()->presign_get( 'b', '/a/file.zip', 60 )
		);
	}

	public function test_spaces_and_unicode_in_keys_are_percent_encoded(): void {
		$url = $this->signer()->presign_get( 'b', 'my folder/naïve café.mp3', 60 );

		$this->assertStringContainsString( 'my%20folder/', $url );
		$this->assertStringContainsString( 'na%C3%AFve%20caf%C3%A9.mp3', $url );
	}

	public function test_query_parameters_are_sorted_canonically(): void {
		$request = $this->signer()->sign_list_objects( 'b', 100, 'p/', '/', 'tok' );

		// continuation-token < delimiter < list-type < max-keys < prefix
		$this->assertStringContainsString(
			'?continuation-token=tok&delimiter=%2F&list-type=2&max-keys=100&prefix=p%2F',
			$request->url
		);
	}

	public function test_list_objects_clamps_max_keys_to_the_s3_limit(): void {
		$this->assertStringContainsString( 'max-keys=1000', $this->signer()->sign_list_objects( 'b', 99999 )->url );
		$this->assertStringContainsString( 'max-keys=1', $this->signer()->sign_list_objects( 'b', 0 )->url );
	}

	/* ─── Signed header set ─────────────────────────────────────────── */

	public function test_mandatory_headers_are_always_signed(): void {
		$request = $this->signer()->sign( Method::GET, 'b', 'k' );

		$this->assertSame( self::ENDPOINT, $request->headers['host'] );
		$this->assertSame( self::AMZ_DATE, $request->headers['x-amz-date'] );
		$this->assertArrayHasKey( 'x-amz-content-sha256', $request->headers );
	}

	public function test_caller_headers_are_signed_and_lowercased(): void {
		$request = $this->signer()->sign( Method::PUT, 'b', 'k', array(), 'body', array( 'Content-Type' => 'audio/wav' ) );

		$this->assertSame( 'audio/wav', $request->headers['content-type'] );
		$this->assertStringContainsString(
			'SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date',
			$request->headers['Authorization']
		);
	}

	public function test_a_caller_cannot_override_the_host_header(): void {
		$request = $this->signer()->sign( Method::GET, 'b', 'k', array(), '', array( 'Host' => 'evil.example.com' ) );

		$this->assertSame( self::ENDPOINT, $request->headers['host'] );
	}

	public function test_signed_request_exposes_curl_shaped_headers(): void {
		$headers = $this->signer()->sign_delete_object( 'b', 'k' )->curl_headers();

		$this->assertContains( 'host: ' . self::ENDPOINT, $headers );
		$this->assertSame( Method::DELETE, $this->signer()->sign_delete_object( 'b', 'k' )->method );
	}

	public function test_signed_request_header_lookup_is_case_insensitive(): void {
		$request = $this->signer()->sign_delete_object( 'b', 'k' );

		$this->assertSame( $request->headers['Authorization'], $request->header( 'AUTHORIZATION' ) );
		$this->assertNull( $request->header( 'x-nonexistent' ) );
	}

	/* ─── Multipart assembly ────────────────────────────────────────── */

	public function test_complete_multipart_sorts_parts_and_normalises_etags(): void {
		$request = $this->signer()->sign_complete_multipart_upload(
			'b',
			'k',
			'UP-1',
			array(
				array( 'PartNumber' => 2, 'ETag' => '"bbb"' ),
				array( 'PartNumber' => 1, 'ETag' => 'aaa' ),
			)
		);

		$this->assertSame(
			'<CompleteMultipartUpload>'
			. '<Part><PartNumber>1</PartNumber><ETag>&quot;aaa&quot;</ETag></Part>'
			. '<Part><PartNumber>2</PartNumber><ETag>&quot;bbb&quot;</ETag></Part>'
			. '</CompleteMultipartUpload>',
			$request->body
		);
	}

	public function test_complete_multipart_rejects_an_empty_part_list(): void {
		$this->expectException( \InvalidArgumentException::class );

		$this->signer()->sign_complete_multipart_upload( 'b', 'k', 'UP-1', array() );
	}

	public function test_abort_multipart_carries_the_upload_id(): void {
		$request = $this->signer()->sign_abort_multipart_upload( 'b', 'k', 'UP-1' );

		$this->assertSame( Method::DELETE, $request->method );
		$this->assertStringContainsString( 'uploadId=UP-1', $request->url );
	}

	/* ─── Content-Disposition passthrough ───────────────────────────── */

	public function test_content_disposition_delegates_to_the_dedicated_class(): void {
		$this->assertSame(
			ContentDisposition::attachment( 'Naïve Café.wav' ),
			Signer::content_disposition( 'Naïve Café.wav' )
		);
	}

	public function test_download_filename_reaches_the_presigned_url(): void {
		$url = $this->signer()->presign_get( 'b', 'k', 60, 'My File.zip' );

		$this->assertStringContainsString( 'response-content-disposition=', $url );
		$this->assertStringContainsString( 'My%2520File.zip', $url );
	}

	public function test_download_filename_changes_the_signature(): void {
		$this->assertNotSame(
			$this->signer()->presign_get( 'b', 'k', 60 ),
			$this->signer()->presign_get( 'b', 'k', 60, 'Named.zip' )
		);
	}

	/* ─── Method enum ───────────────────────────────────────────────── */

	public function test_method_body_expectations(): void {
		$this->assertTrue( Method::PUT->has_body() );
		$this->assertTrue( Method::POST->has_body() );
		$this->assertFalse( Method::GET->has_body() );
		$this->assertFalse( Method::DELETE->has_body() );
		$this->assertFalse( Method::HEAD->has_body() );
	}
}
