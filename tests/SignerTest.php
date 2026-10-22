<?php
/**
 * Signer test suite.
 *
 * The golden signatures below were produced by this library and verified
 * byte-for-byte against the signer that has been serving Cloudflare R2
 * downloads in production. Treat any change to them as a breaking change:
 * a differing signature means every presigned URL stops working.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\S3Signer\ContentDisposition;
use SugarCommerce\S3Signer\Method;
use SugarCommerce\S3Signer\Signer;

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

	public function test_list_parts_is_a_signed_get_for_that_upload(): void {
		$request = $this->signer()->sign_list_parts( 'b', 'k', 'UP-1' );

		$this->assertSame( Method::GET, $request->method );
		$this->assertStringContainsString( 'uploadId=UP-1', $request->url );
		$this->assertStringContainsString( 'max-parts=1000', $request->url );
		$this->assertStringNotContainsString( 'part-number-marker', $request->url, 'The first page has no marker.' );
		$this->assertStringStartsWith( 'AWS4-HMAC-SHA256', (string) $request->header( 'Authorization' ) );
	}

	public function test_list_parts_pages_by_marker_and_clamps_the_page(): void {
		$request = $this->signer()->sign_list_parts( 'b', 'k', 'UP-1', 50_000, 1000 );

		$this->assertStringContainsString( 'part-number-marker=1000', $request->url );
		$this->assertStringContainsString( 'max-parts=1000', $request->url );
		$this->assertStringContainsString( 'max-parts=1&', $this->signer()->sign_list_parts( 'b', 'k', 'UP-1', 0 )->url );
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

	/* ─── Inline, origin and copy (1.2.0) ───────────────────────────── */

	public function test_presign_inline_names_the_type_and_asks_to_render(): void {
		$url = $this->signer()->presign_inline( 'files', 'a/b.bin', 3600, 'audio/mpeg' );

		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $query );

		$this->assertSame( 'audio/mpeg', $query['response-content-type'] );
		$this->assertSame( 'inline', $query['response-content-disposition'] );
		$this->assertSame( '3600', $query['X-Amz-Expires'] );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $query['X-Amz-Signature'] );
	}

	/**
	 * The type is inside the signature: changing it in a copied URL must
	 * break it, or the URL could be made to serve anything as HTML.
	 */
	public function test_the_inline_type_is_signed(): void {
		$audio = $this->signer()->presign_inline( 'files', 'k', 60, 'audio/mpeg' );
		$html  = $this->signer()->presign_inline( 'files', 'k', 60, 'text/html' );

		// The signature is the last query parameter, 64 hex characters.
		$this->assertNotSame( substr( $audio, -64 ), substr( $html, -64 ) );
	}

	/* ─── Cacheable (1.3.0) ─────────────────────────────────────────── */

	/**
	 * The whole point: two page loads in the same hour produce the same URL,
	 * so the browser's cached copy is used and storage is not asked again.
	 */
	public function test_a_cacheable_url_is_the_same_all_window(): void {
		$signer = $this->signer( null );
		$start  = 1_760_000_400; // A multiple of 3600.

		$first = $signer->presign_cacheable( 'files', 'a/b.png', 3600, 'image/png', $start );
		$last  = $signer->presign_cacheable( 'files', 'a/b.png', 3600, 'image/png', $start + 3599 );
		$next  = $signer->presign_cacheable( 'files', 'a/b.png', 3600, 'image/png', $start + 3600 );

		$this->assertSame( $first, $last );
		$this->assertNotSame( $first, $next );
	}

	public function test_a_cacheable_url_says_how_long_to_keep_it_and_outlives_that(): void {
		$url = $this->signer( null )->presign_cacheable( 'files', 'k', 3600, 'image/webp', 1_760_000_400 + 10 );

		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $query );

		$this->assertSame( 'private, max-age=3600', $query['response-cache-control'] );
		$this->assertSame( 'image/webp', $query['response-content-type'] );
		$this->assertSame( 'inline', $query['response-content-disposition'] );
		$this->assertSame( '7200', $query['X-Amz-Expires'] );
		$this->assertSame( gmdate( 'Ymd\THis\Z', 1_760_000_400 ), $query['X-Amz-Date'], 'Signed at the start of the window.' );
	}

	/**
	 * The cache instruction is signed, so nobody can edit a copied URL into
	 * one that tells a shared cache to keep a private file.
	 */
	public function test_the_cache_instruction_is_signed(): void {
		$url = $this->signer( null )->presign_cacheable( 'files', 'k', 3600, 'image/png', 1_760_000_400 );

		$this->assertSame( $url, $this->signer( null )->presign_cacheable( 'files', 'k', 3600, 'image/png', 1_760_000_400 ) );
		$this->assertNotSame(
			substr( $url, -64 ),
			substr( $this->signer( null )->presign_cacheable( 'files', 'k', 1800, 'image/png', 1_760_000_400 ), -64 )
		);
	}

	public function test_a_window_too_long_to_sign_twice_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		$this->signer()->presign_cacheable( 'files', 'k', 4 * 86400, 'image/png' );
	}

	public function test_origin_is_where_urls_for_the_bucket_point(): void {
		$signer = $this->signer();

		$this->assertStringStartsWith( $signer->origin( 'files' ) . '/', $signer->presign_get( 'files', 'k', 60 ) );
	}

	public function test_a_copy_names_its_source_and_replaces_metadata(): void {
		$request = $this->signer()->sign_copy_object( 'private', 'acct/live/ab cd.wav', 'public', 'p/acct/ab.wav', 'audio/wav', 'public, max-age=31536000, immutable' );

		$this->assertSame( 'PUT', $request->method->value );
		$this->assertSame( '/private/acct/live/ab%20cd.wav', $request->headers['x-amz-copy-source'] );
		$this->assertSame( 'REPLACE', $request->headers['x-amz-metadata-directive'] );
		$this->assertSame( 'audio/wav', $request->headers['content-type'] );
		$this->assertSame( 'public, max-age=31536000, immutable', $request->headers['cache-control'] );
		$this->assertStringContainsString( 'x-amz-copy-source', $request->headers['Authorization'] ?? $request->headers['authorization'] ?? '' );
	}

	/* ─── AWS's own vectors (1.4.0) ─────────────────────────────────── */

	/**
	 * The examples in AWS's SigV4 documentation for S3, signed by an
	 * implementation that is not this one. The golden vectors above prove
	 * nothing changed; these prove it was right to begin with.
	 */
	#[DataProvider( 'aws_vectors' )]
	public function test_aws_documentation_vectors( \Closure $sign, string $signature ): void {
		$signer = new Signer( self::ACCESS_KEY, self::SECRET_KEY, 's3.amazonaws.com', 'us-east-1', 1369353600, \SugarCommerce\S3Signer\AddressingStyle::VirtualHosted );

		$this->assertStringEndsWith( $signature, $sign( $signer ) );
	}

	/** @return array<string, array{0: \Closure, 1: string}> */
	public static function aws_vectors(): array {
		return array(
			'presigned GET'  => array(
				static fn ( Signer $s ): string => $s->presign( Method::GET, 'examplebucket', 'test.txt', array(), 86400 ),
				'aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404',
			),
			'GET with range' => array(
				static fn ( Signer $s ): string => (string) $s->sign( Method::GET, 'examplebucket', 'test.txt', array(), '', array( 'range' => 'bytes=0-9' ) )->header( 'Authorization' ),
				'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
			),
			'GET lifecycle'  => array(
				static fn ( Signer $s ): string => (string) $s->sign( Method::GET, 'examplebucket', '', array( 'lifecycle' => '' ) )->header( 'Authorization' ),
				'fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543',
			),
			'list objects'   => array(
				static fn ( Signer $s ): string => (string) $s->sign( Method::GET, 'examplebucket', '', array( 'max-keys' => '2', 'prefix' => 'J' ) )->header( 'Authorization' ),
				'34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7',
			),
		);
	}

	/* ─── Hardening (1.4.0) ─────────────────────────────────────────── */

	public function test_a_dumped_signer_does_not_show_its_keys(): void {
		$dump = print_r( $this->signer(), true );

		$this->assertStringNotContainsString( self::SECRET_KEY, $dump );
		$this->assertStringNotContainsString( self::ACCESS_KEY, $dump );
		$this->assertStringContainsString( self::ENDPOINT, $dump );
	}

	/**
	 * `uploads/<user>/` + a name of `../<other>/x` signs a path that a
	 * normalising client or gateway reads as somebody else's key.
	 */
	#[DataProvider( 'dot_segment_paths' )]
	public function test_a_dot_segment_is_refused( \Closure $sign ): void {
		$this->expectException( \InvalidArgumentException::class );

		$sign( $this->signer() );
	}

	/** @return array<string, array{0: \Closure}> */
	public static function dot_segment_paths(): array {
		return array(
			'presigned put'   => array( static fn ( Signer $s ): string => $s->presign_put( 'b', 'uploads/u1/../u2/avatar.png' ) ),
			'presigned get'   => array( static fn ( Signer $s ): string => $s->presign_get( 'b', '../secret.zip' ) ),
			'trailing dots'   => array( static fn ( Signer $s ): string => $s->presign_get( 'b', 'a/..' ) ),
			'single dot'      => array( static fn ( Signer $s ): string => $s->presign_get( 'b', 'a/./b' ) ),
			'bucket'          => array( static fn ( Signer $s ): string => $s->presign_get( '..', 'x' ) ),
			'signed delete'   => array( static fn ( Signer $s ): mixed => $s->sign_delete_object( 'b', 'a/../../other/x' ) ),
			'copy source key' => array( static fn ( Signer $s ): mixed => $s->sign_copy_object( 'b', '../x', 'b', 'y' ) ),
		);
	}

	public function test_dots_inside_a_segment_are_still_fine(): void {
		$url = $this->signer()->presign_get( 'b', 'a/..b/c.../.hidden', 60 );

		$this->assertStringContainsString( '/b/a/..b/c.../.hidden?', $url );
	}

	public function test_an_r2_account_id_that_is_not_a_label_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		Signer::r2( self::ACCESS_KEY, self::SECRET_KEY, 'evil.example/' );
	}

	public function test_an_inline_content_type_with_a_line_break_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		$this->signer()->presign_inline( 'b', 'a.mp3', 60, "audio/mpeg\r\nSet-Cookie: a=b" );
	}

	public function test_query_names_sort_as_strings_not_numbers(): void {
		$url = $this->signer()->presign( Method::GET, 'b', 'k', array( '10' => 'a', '9' => 'b' ), 60 );

		$this->assertStringContainsString( '?10=a&9=b&X-Amz-Algorithm', $url );
	}
}
