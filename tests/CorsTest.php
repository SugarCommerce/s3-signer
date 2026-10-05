<?php
/**
 * Bucket CORS rules, policies and the requests that carry them.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.1.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\S3Signer\Cors\{Policy, Rule};
use SugarCommerce\S3Signer\Method;
use SugarCommerce\S3Signer\Signer;

final class CorsTest extends TestCase {

	/** Public AWS documentation example credentials — not live. */
	private const ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
	private const SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
	private const ENDPOINT   = 'abc123.r2.cloudflarestorage.com';
	private const TIMESTAMP  = 1700000000;

	private const ORIGIN = 'https://example.com';

	private function signer(): Signer {
		return new Signer( self::ACCESS_KEY, self::SECRET_KEY, self::ENDPOINT, 'auto', self::TIMESTAMP );
	}

	/* ─── Rules ─────────────────────────────────────────────────────── */

	public function test_a_rule_needs_an_origin(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Rule( origins: array(), methods: array( 'GET' ) );
	}

	public function test_a_rule_needs_a_method(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Rule( origins: array( '*' ), methods: array() );
	}

	public function test_a_rule_refuses_a_method_s3_will_reject(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Rule( origins: array( '*' ), methods: array( 'PATCH' ) );
	}

	public function test_a_wildcard_origin_covers_everything(): void {
		$rule = new Rule( origins: array( '*' ), methods: array( 'GET' ) );

		$this->assertTrue( $rule->covers( self::ORIGIN ) );
		$this->assertTrue( $rule->covers( 'https://anything.test' ) );
	}

	/**
	 * S3 does no subdomain matching, so a rule written that way silently
	 * matches nothing at all.
	 */
	public function test_a_subdomain_pattern_matches_nothing(): void {
		$rule = new Rule( origins: array( 'https://*.example.com' ), methods: array( 'GET' ) );

		$this->assertFalse( $rule->covers( 'https://app.example.com' ) );
	}

	public function test_an_origin_has_to_match_exactly(): void {
		$rule = new Rule( origins: array( self::ORIGIN ), methods: array( 'GET' ) );

		$this->assertTrue( $rule->covers( self::ORIGIN ) );
		$this->assertFalse( $rule->covers( 'https://example.com:443' ) );
		$this->assertFalse( $rule->covers( 'http://example.com' ) );
	}

	public function test_allows_needs_both_the_origin_and_the_method(): void {
		$rule = new Rule( origins: array( self::ORIGIN ), methods: array( 'PUT' ) );

		$this->assertTrue( $rule->allows( self::ORIGIN, 'PUT' ) );
		$this->assertTrue( $rule->allows( self::ORIGIN, 'put' ) );
		$this->assertFalse( $rule->allows( self::ORIGIN, 'GET' ) );
		$this->assertFalse( $rule->allows( 'https://other.test', 'PUT' ) );
	}

	public function test_exposed_headers_are_matched_case_insensitively(): void {
		$rule = new Rule( origins: array( '*' ), methods: array( 'PUT' ), expose: array( 'etag' ) );

		$this->assertTrue( $rule->exposes( 'ETag' ) );
		$this->assertFalse( $rule->exposes( 'Content-Length' ) );
	}

	/**
	 * The one line that makes a multipart upload work.
	 */
	public function test_browser_upload_exposes_the_etag(): void {
		$rule = Rule::browser_upload( array( self::ORIGIN ) );

		$this->assertTrue( $rule->exposes( 'ETag' ) );
		$this->assertTrue( $rule->allows( self::ORIGIN, 'PUT' ) );
		$this->assertTrue( $rule->allows( self::ORIGIN, 'POST' ) );
	}

	public function test_browser_read_exposes_what_a_reader_needs(): void {
		$rule = Rule::browser_read();

		$this->assertTrue( $rule->allows( 'https://anything.test', 'GET' ) );
		$this->assertTrue( $rule->exposes( 'Content-Length' ) );
		$this->assertTrue( $rule->exposes( 'Last-Modified' ) );
	}

	public function test_a_rule_round_trips_through_its_array_form(): void {
		$rule = Rule::browser_upload( array( self::ORIGIN ) );

		$this->assertEquals( $rule, Rule::from_array( $rule->to_array() ) );
	}

	public function test_the_array_form_omits_what_is_not_set(): void {
		$rule = new Rule( origins: array( '*' ), methods: array( 'GET' ), headers: array(), max_age: 0 );

		$this->assertArrayNotHasKey( 'AllowedHeaders', $rule->to_array() );
		$this->assertArrayNotHasKey( 'ExposeHeaders', $rule->to_array() );
		$this->assertArrayNotHasKey( 'MaxAgeSeconds', $rule->to_array() );
		$this->assertArrayNotHasKey( 'ID', $rule->to_array() );
	}

	/* ─── Policies ──────────────────────────────────────────────────── */

	public function test_a_policy_counts_and_iterates_its_rules(): void {
		$policy = Policy::for_browser_uploads( array( self::ORIGIN ) );

		$this->assertCount( 2, $policy );
		$this->assertContainsOnlyInstancesOf( Rule::class, iterator_to_array( $policy ) );
	}

	public function test_a_policy_refuses_more_rules_than_a_bucket_takes(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Policy( array_fill( 0, Policy::MAX_RULES + 1, Rule::browser_read() ) );
	}

	public function test_a_policy_reports_every_origin_and_method(): void {
		$policy = Policy::for_browser_uploads( array( self::ORIGIN ) );

		$this->assertSame( array( self::ORIGIN, '*' ), $policy->origins() );
		$this->assertSame( array( 'PUT', 'POST', 'GET', 'HEAD' ), $policy->methods() );
	}

	public function test_exposure_is_scoped_to_the_method(): void {
		// ETag on a read-only rule does nothing for an upload, and a check
		// that ignored the method would call this configuration good.
		$policy = new Policy( array(
			new Rule( origins: array( '*' ), methods: array( 'GET' ), expose: array( 'ETag' ) ),
			new Rule( origins: array( '*' ), methods: array( 'PUT' ) ),
		) );

		$this->assertTrue( $policy->exposes( self::ORIGIN, 'GET', 'ETag' ) );
		$this->assertFalse( $policy->exposes( self::ORIGIN, 'PUT', 'ETag' ) );
	}

	/* ─── The question a deployment check asks ──────────────────────── */

	public function test_a_browser_upload_policy_supports_multipart(): void {
		$result = Policy::for_browser_uploads( array( self::ORIGIN ) )->supports_multipart_upload( self::ORIGIN );

		$this->assertTrue( $result['ok'] );
		$this->assertSame( '', $result['reason'] );
	}

	public function test_no_configuration_at_all_is_reported_plainly(): void {
		$result = ( new Policy() )->supports_multipart_upload( self::ORIGIN );

		$this->assertFalse( $result['ok'] );
		$this->assertStringContainsString( 'no CORS configuration', $result['reason'] );
	}

	public function test_a_policy_for_another_origin_does_not_count(): void {
		$result = Policy::for_browser_uploads( array( 'https://other.test' ) )
			->supports_multipart_upload( self::ORIGIN );

		$this->assertFalse( $result['ok'] );
		$this->assertStringContainsString( 'PUT', $result['reason'] );
	}

	/**
	 * The failure this whole class exists to catch: PUT allowed, ETag not
	 * exposed. Every part uploads and the upload then fails at assembly.
	 */
	public function test_put_without_an_exposed_etag_is_caught(): void {
		$policy = new Policy( array(
			new Rule(
				origins: array( self::ORIGIN ),
				methods: array( 'PUT', 'POST' ),
				headers: array( '*' ),
			),
		) );

		$result = $policy->supports_multipart_upload( self::ORIGIN );

		$this->assertFalse( $result['ok'] );
		$this->assertStringContainsString( 'ETag', $result['reason'] );
	}

	public function test_every_origin_has_to_be_supported(): void {
		$policy = Policy::for_browser_uploads( array( self::ORIGIN ) );

		$this->assertTrue( $policy->supports_multipart_upload_from( array( self::ORIGIN ) )['ok'] );

		$result = $policy->supports_multipart_upload_from( array( self::ORIGIN, 'https://second.test' ) );

		$this->assertFalse( $result['ok'] );
		$this->assertStringContainsString( 'https://second.test', $result['reason'] );
	}

	public function test_no_origins_to_check_is_not_a_pass(): void {
		$this->assertFalse( Policy::for_browser_uploads( array( self::ORIGIN ) )->supports_multipart_upload_from( array() )['ok'] );
	}

	/* ─── Console JSON (1.3.0) ──────────────────────────────────────── */

	public function test_the_console_json_is_a_list_of_rules_without_ids(): void {
		$rules = json_decode( ( new Policy( array( Rule::browser_upload( array( self::ORIGIN ) ) ) ) )->to_console_json(), true );

		$this->assertIsList( $rules );
		$this->assertCount( 1, $rules );
		$this->assertArrayNotHasKey( 'ID', $rules[0] );
		$this->assertSame( array( self::ORIGIN ), $rules[0]['AllowedOrigins'] );
		$this->assertContains( 'PUT', $rules[0]['AllowedMethods'] );
		$this->assertContains( 'ETag', $rules[0]['ExposeHeaders'] );
	}

	public function test_the_console_json_keeps_urls_readable(): void {
		$this->assertStringContainsString( '"https://', Policy::for_browser_uploads( array( self::ORIGIN ) )->to_console_json() );
	}

	/* ─── XML ───────────────────────────────────────────────────────── */

	public function test_the_xml_carries_every_field(): void {
		$xml = Policy::for_browser_uploads( array( self::ORIGIN ) )->to_xml();

		$this->assertStringContainsString( '<CORSConfiguration', $xml );
		$this->assertStringContainsString( '<AllowedOrigin>https://example.com</AllowedOrigin>', $xml );
		$this->assertStringContainsString( '<AllowedMethod>PUT</AllowedMethod>', $xml );
		$this->assertStringContainsString( '<ExposeHeader>ETag</ExposeHeader>', $xml );
		$this->assertStringContainsString( '<MaxAgeSeconds>3600</MaxAgeSeconds>', $xml );
		$this->assertStringContainsString( '<ID>BrowserUpload</ID>', $xml );
	}

	public function test_the_xml_escapes_its_values(): void {
		$policy = new Policy( array(
			new Rule( origins: array( 'https://a.test/?a=1&b=2' ), methods: array( 'GET' ) ),
		) );

		$this->assertStringContainsString( '&amp;', $policy->to_xml() );
		$this->assertStringNotContainsString( '=1&b=', $policy->to_xml() );
	}

	public function test_a_policy_round_trips_through_xml(): void {
		$policy = Policy::for_browser_uploads( array( self::ORIGIN ) );

		$this->assertEquals( $policy, Policy::from_xml( $policy->to_xml() ) );
	}

	public function test_an_empty_body_is_an_empty_policy(): void {
		// What a bucket with no configuration returns.
		$this->assertCount( 0, Policy::from_xml( '' ) );
		$this->assertCount( 0, Policy::from_xml( "  \n " ) );
	}

	public function test_unparseable_xml_throws(): void {
		$this->expectException( \RuntimeException::class );

		Policy::from_xml( '<CORSConfiguration><oops' );
	}

	public function test_a_real_response_parses(): void {
		$xml = <<<'XML'
			<?xml version="1.0" encoding="UTF-8"?>
			<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
			  <CORSRule>
			    <AllowedOrigin>https://example.com</AllowedOrigin>
			    <AllowedMethod>PUT</AllowedMethod>
			    <AllowedMethod>POST</AllowedMethod>
			    <AllowedHeader>*</AllowedHeader>
			    <ExposeHeader>ETag</ExposeHeader>
			    <MaxAgeSeconds>3600</MaxAgeSeconds>
			  </CORSRule>
			</CORSConfiguration>
			XML;

		$policy = Policy::from_xml( $xml );

		$this->assertCount( 1, $policy );
		$this->assertTrue( $policy->supports_multipart_upload( self::ORIGIN )['ok'] );
	}

	/* ─── Signing ───────────────────────────────────────────────────── */

	public function test_reading_the_configuration_signs_a_get_with_the_cors_subresource(): void {
		$request = $this->signer()->sign_get_bucket_cors( 'my-bucket' );

		$this->assertSame( Method::GET, $request->method );
		$this->assertStringContainsString( '/my-bucket?cors', $request->url );
		$this->assertSame( '', $request->body );
	}

	public function test_writing_the_configuration_signs_a_put_carrying_the_xml(): void {
		$policy  = Policy::for_browser_uploads( array( self::ORIGIN ) );
		$request = $this->signer()->sign_put_bucket_cors( 'my-bucket', $policy );

		$this->assertSame( Method::PUT, $request->method );
		$this->assertStringContainsString( '?cors', $request->url );
		$this->assertSame( $policy->to_xml(), $request->body );
		$this->assertSame( 'application/xml', $request->header( 'content-type' ) );
	}

	/**
	 * AWS refuses PutBucketCors without it.
	 */
	public function test_writing_the_configuration_sends_a_content_md5(): void {
		$policy  = Policy::for_browser_uploads( array( self::ORIGIN ) );
		$request = $this->signer()->sign_put_bucket_cors( 'my-bucket', $policy );

		$this->assertSame(
			base64_encode( (string) hash( 'md5', $policy->to_xml(), true ) ),
			$request->header( 'content-md5' )
		);
	}

	public function test_the_body_hash_covers_the_xml(): void {
		$policy  = Policy::for_browser_uploads( array( self::ORIGIN ) );
		$request = $this->signer()->sign_put_bucket_cors( 'my-bucket', $policy );

		$this->assertSame( hash( 'sha256', $policy->to_xml() ), $request->header( 'x-amz-content-sha256' ) );
	}

	public function test_the_signature_covers_the_body(): void {
		$signer = $this->signer();

		$one = $signer->sign_put_bucket_cors( 'my-bucket', Policy::for_browser_uploads( array( self::ORIGIN ) ) );
		$two = $signer->sign_put_bucket_cors( 'my-bucket', Policy::for_browser_uploads( array( 'https://other.test' ) ) );

		$this->assertNotSame( $one->header( 'authorization' ), $two->header( 'authorization' ) );
	}

	public function test_removing_the_configuration_signs_a_delete(): void {
		$request = $this->signer()->sign_delete_bucket_cors( 'my-bucket' );

		$this->assertSame( Method::DELETE, $request->method );
		$this->assertStringContainsString( '?cors', $request->url );
	}
}
