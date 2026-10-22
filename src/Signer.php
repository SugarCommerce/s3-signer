<?php
/**
 * AWS Signature Version 4 signing for S3-compatible object storage.
 *
 * @package   SugarCommerce\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\S3Signer;

use SugarCommerce\S3Signer\Cors\Policy;

/**
 * Class Signer
 *
 * Produces AWS SigV4 signatures for S3-compatible storage — Cloudflare
 * R2, AWS S3, Backblaze B2, DigitalOcean Spaces, MinIO, and anything
 * else speaking the same protocol.
 *
 * This library signs. It never performs I/O, so there is no HTTP client
 * to configure, no SDK to update, and nothing to mock in your tests.
 * Two families of method:
 *
 *   - `presign_*()` returns a URL with the signature in the query
 *     string. Hand it to a browser — that's how downloads and
 *     direct-to-storage uploads work without proxying bytes through PHP.
 *   - `sign_*()` returns a {@see SignedRequest} with the signature in an
 *     `Authorization` header, for calls your server makes itself.
 *
 * Path-style URLs (`host/<bucket>/<key>`) are used throughout. That is
 * R2's default and avoids per-bucket DNS setup; AWS still accepts it.
 *
 * Construction is free — no network, no state beyond the credentials.
 *
 * Typical use:
 *
 *   use SugarCommerce\S3Signer\Signer;
 *
 *   $signer = new Signer(
 *       access_key: $key,
 *       secret_key: $secret,
 *       endpoint:   '<account>.r2.cloudflarestorage.com',
 *   );
 *
 *   // 60-second download link, saved as "Album Master.wav"
 *   $url = $signer->presign_get( 'my-bucket', 'masters/a1.wav', 60, 'Album Master.wav' );
 *
 *   // A DELETE your server executes
 *   $req = $signer->sign_delete_object( 'my-bucket', 'masters/a1.wav' );
 *
 * @since 1.0.0
 */
final readonly class Signer {

	/**
	 * SigV4 algorithm identifier. First line of every string-to-sign.
	 */
	private const string ALGORITHM = 'AWS4-HMAC-SHA256';

	/**
	 * Service name in the credential scope. Always 's3' here.
	 */
	private const string SERVICE = 's3';

	/**
	 * Payload placeholder for query-string signing.
	 *
	 * Presigned URLs are handed to a browser, so the body cannot be
	 * hashed ahead of time. S3 defines this literal for that case.
	 */
	private const string UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';

	/**
	 * Longest presigned-URL lifetime SigV4 permits, in seconds (7 days).
	 */
	public const int MAX_EXPIRES = 604800;

	/**
	 * Normalised endpoint host, without scheme, port-path or trailing slash.
	 *
	 * @var string
	 */
	private string $endpoint;

	/**
	 * Build the signer.
	 *
	 * Credentials carry `#[\SensitiveParameter]` so they are scrubbed
	 * from stack traces if anything downstream throws.
	 *
	 * Consider the provider factories — {@see self::r2()},
	 * {@see self::aws()}, {@see self::backblaze()},
	 * {@see self::digitalocean()}, {@see self::minio()} — which set the
	 * endpoint and addressing style correctly for you.
	 *
	 * @since 1.0.0
	 *
	 * @param string          $access_key Access key ID.
	 * @param string          $secret_key Secret access key.
	 * @param string          $endpoint   Host, e.g.
	 *                                    `<account>.r2.cloudflarestorage.com`.
	 *                                    A scheme or trailing slash is
	 *                                    tolerated and stripped.
	 * @param string          $region     Region name. `auto` suits
	 *                                    Cloudflare R2; AWS needs the real
	 *                                    region (`eu-west-2`).
	 * @param int|null        $timestamp  Fixed Unix time to sign at. For
	 *                                    tests and reproducible fixtures —
	 *                                    leave null in production or every
	 *                                    signature shares one eventually
	 *                                    expired date.
	 * @param AddressingStyle $addressing Where the bucket goes. Defaults to
	 *                                    path-style; AWS, Backblaze and
	 *                                    Spaces want virtual-hosted.
	 *
	 * @throws \InvalidArgumentException On empty credentials, an unusable
	 *                                   endpoint, or a region containing
	 *                                   characters that would corrupt the
	 *                                   credential scope.
	 */
	public function __construct(
		#[\SensitiveParameter]
		private string $access_key,
		#[\SensitiveParameter]
		private string $secret_key,
		string $endpoint,
		private string $region = 'auto',
		private ?int $timestamp = null,
		private AddressingStyle $addressing = AddressingStyle::Path,
	) {
		if ( '' === trim( $access_key ) || '' === trim( $secret_key ) ) {
			throw new \InvalidArgumentException( 'S3 credentials cannot be empty.' );
		}

		// The region is interpolated into the credential scope, which is
		// signed. A stray slash there silently produces a scope the
		// provider will not recognise.
		if ( 1 !== preg_match( '/^[A-Za-z0-9\-]+$/', $region ) ) {
			throw new \InvalidArgumentException( 'S3 region must contain only letters, digits and hyphens.' );
		}

		$this->endpoint = self::normalize_endpoint( $endpoint );
	}

	/* ─── Provider factories ────────────────────────────────────────── */

	/**
	 * Cloudflare R2. Path-style against the account endpoint.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $access_key Access key ID.
	 * @param string   $secret_key Secret access key.
	 * @param string   $account_id Cloudflare account id.
	 * @param int|null $timestamp  Fixed signing time, for tests.
	 *
	 * @return self
	 *
	 * @throws \InvalidArgumentException On an account id that is not a
	 *                                   single DNS label, or as the
	 *                                   constructor does.
	 */
	public static function r2(
		#[\SensitiveParameter] string $access_key,
		#[\SensitiveParameter] string $secret_key,
		string $account_id,
		?int $timestamp = null,
	): self {
		// The id becomes the first label of the host. Anything but a plain
		// label — `evil.example/` — would move the host somewhere else, and
		// the signed requests with it.
		if ( ! Provider::is_label( $account_id ) ) {
			throw new \InvalidArgumentException( 'A Cloudflare account id is letters, digits and hyphens only.' );
		}

		return new self(
			$access_key,
			$secret_key,
			$account_id . '.r2.cloudflarestorage.com',
			'auto',
			$timestamp,
			AddressingStyle::Path
		);
	}

	/**
	 * Amazon S3. Virtual-hosted, since path-style is deprecated for
	 * buckets created in newer regions.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $access_key Access key ID.
	 * @param string   $secret_key Secret access key.
	 * @param string   $region     AWS region, e.g. `eu-west-2`.
	 * @param int|null $timestamp  Fixed signing time, for tests.
	 *
	 * @return self
	 */
	public static function aws(
		#[\SensitiveParameter] string $access_key,
		#[\SensitiveParameter] string $secret_key,
		string $region,
		?int $timestamp = null,
	): self {
		return new self(
			$access_key,
			$secret_key,
			's3.' . $region . '.amazonaws.com',
			$region,
			$timestamp,
			AddressingStyle::VirtualHosted
		);
	}

	/**
	 * Backblaze B2 via its S3-compatible API. Virtual-hosted.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $access_key Application key ID.
	 * @param string   $secret_key Application key.
	 * @param string   $region     B2 region, e.g. `us-west-004`.
	 * @param int|null $timestamp  Fixed signing time, for tests.
	 *
	 * @return self
	 */
	public static function backblaze(
		#[\SensitiveParameter] string $access_key,
		#[\SensitiveParameter] string $secret_key,
		string $region,
		?int $timestamp = null,
	): self {
		return new self(
			$access_key,
			$secret_key,
			's3.' . $region . '.backblazeb2.com',
			$region,
			$timestamp,
			AddressingStyle::VirtualHosted
		);
	}

	/**
	 * DigitalOcean Spaces. Virtual-hosted.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $access_key Access key ID.
	 * @param string   $secret_key Secret access key.
	 * @param string   $region     Spaces region, e.g. `ams3`.
	 * @param int|null $timestamp  Fixed signing time, for tests.
	 *
	 * @return self
	 */
	public static function digitalocean(
		#[\SensitiveParameter] string $access_key,
		#[\SensitiveParameter] string $secret_key,
		string $region,
		?int $timestamp = null,
	): self {
		return new self(
			$access_key,
			$secret_key,
			$region . '.digitaloceanspaces.com',
			$region,
			$timestamp,
			AddressingStyle::VirtualHosted
		);
	}

	/**
	 * MinIO, Ceph, or any self-hosted S3 gateway. Path-style.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $access_key Access key ID.
	 * @param string   $secret_key Secret access key.
	 * @param string   $endpoint   Host, optionally with a port.
	 * @param string   $region     Region label. MinIO defaults to `us-east-1`.
	 * @param int|null $timestamp  Fixed signing time, for tests.
	 *
	 * @return self
	 */
	public static function minio(
		#[\SensitiveParameter] string $access_key,
		#[\SensitiveParameter] string $secret_key,
		string $endpoint,
		string $region = 'us-east-1',
		?int $timestamp = null,
	): self {
		return new self( $access_key, $secret_key, $endpoint, $region, $timestamp, AddressingStyle::Path );
	}

	/* ─── Presigned URLs (query-string signing) ─────────────────────── */

	/**
	 * Mint a presigned GET URL.
	 *
	 * Optionally override the filename the browser saves as, without
	 * touching the stored object — S3 and R2 both honour
	 * `response-content-disposition` on a presigned GET. That lets you
	 * store opaque keys (`files/8a3f2c.zip`) and still deliver
	 * `Drum Kit Vol. 2.zip`.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket            Bucket name.
	 * @param string $key               Object key. Leading slash optional.
	 * @param int    $expires_seconds   Validity window from now. Default 60.
	 * @param string $download_filename Filename to force. '' leaves the
	 *                                  browser to infer it from the key.
	 *
	 * @return string Fully-qualified HTTPS URL.
	 *
	 * @throws \InvalidArgumentException As presign() does.
	 */
	public function presign_get( string $bucket, string $key, int $expires_seconds = 60, string $download_filename = '' ): string {
		$query = array();

		if ( '' !== $download_filename ) {
			$query['response-content-disposition'] = self::content_disposition( $download_filename );
		}

		return $this->presign( Method::GET, $bucket, $key, $query, $expires_seconds );
	}

	/**
	 * Mint a presigned GET URL that plays or shows in the browser.
	 *
	 * The counterpart to presign_get() with a filename: that one makes the
	 * browser save the object, this one makes it render it. An `<audio>` or
	 * `<video>` element needs a content type it recognises, and an object
	 * uploaded as `application/octet-stream` has none — so the type is set
	 * on the response rather than on the object, the same way the filename
	 * is.
	 *
	 * @since 1.2.0
	 *
	 * @param string $bucket          Bucket name.
	 * @param string $key             Object key.
	 * @param int    $expires_seconds Validity window. Long enough for the
	 *                                range requests a media element makes
	 *                                while it plays and seeks.
	 * @param string $content_type    What to call it, e.g. `audio/mpeg`. Never
	 *                                one a visitor chose: `text/html` served
	 *                                inline from the bucket's origin is a page
	 *                                on that origin.
	 *
	 * @return string Fully-qualified HTTPS URL.
	 *
	 * @throws \InvalidArgumentException On a content type with a line break
	 *                                   in it, or as presign() does.
	 */
	public function presign_inline( string $bucket, string $key, int $expires_seconds, string $content_type ): string {
		self::assert_header_value( $content_type );

		return $this->presign( Method::GET, $bucket, $key, array(
			'response-content-type'        => $content_type,
			'response-content-disposition' => 'inline',
		), $expires_seconds );
	}

	/**
	 * Mint an inline GET URL that stays the same for a while, so a browser
	 * can cache what it fetched.
	 *
	 * A presigned URL normally carries the second it was signed, so every
	 * page load mints a new one and a browser can never reuse what it
	 * fetched last time — each view is another billable read. Signed at the
	 * start of the current window instead, the URL is identical for the whole
	 * window, and the response says it may be kept that long.
	 *
	 * Valid for two windows from the start of this one, so a copy fetched
	 * in the last second of the window is still fetchable for a full window
	 * after — and never cached past the moment the URL stops working.
	 *
	 * @since 1.3.0
	 *
	 * @param string   $bucket       Bucket name.
	 * @param string   $key          Object key.
	 * @param int      $window       Seconds the URL stays the same, at most
	 *                               half of MAX_EXPIRES.
	 * @param string   $content_type What to call it, e.g. `image/png`.
	 * @param int|null $now          Unix time, for tests. Defaults to the
	 *                               signer's fixed time, then the clock.
	 *
	 * @return string Fully-qualified HTTPS URL.
	 *
	 * @throws \InvalidArgumentException On a window outside 1 second to half
	 *                                   of MAX_EXPIRES, a content type with a
	 *                                   line break in it, or as presign() does.
	 */
	public function presign_cacheable( string $bucket, string $key, int $window, string $content_type, ?int $now = null ): string {
		if ( $window < 1 || 2 * $window > self::MAX_EXPIRES ) {
			throw new \InvalidArgumentException( 'A cacheable URL window must be between 1 second and half of seven days.' );
		}

		self::assert_header_value( $content_type );

		$now   ??= $this->timestamp ?? time();
		$signer = clone( $this, array( 'timestamp' => intdiv( $now, $window ) * $window ) );

		return $signer->presign( Method::GET, $bucket, $key, array(
			'response-content-type'        => $content_type,
			'response-content-disposition' => 'inline',
			'response-cache-control'       => 'private, max-age=' . $window,
		), 2 * $window );
	}

	/**
	 * The scheme and host requests for a bucket go to.
	 *
	 * For a Content-Security-Policy: a page that plays an object from a
	 * presigned URL has to name where that URL points.
	 *
	 * @since 1.2.0
	 *
	 * @param string $bucket Bucket name.
	 *
	 * @return string e.g. `https://files.acct.r2.cloudflarestorage.com`.
	 *
	 * @throws \InvalidArgumentException When the bucket cannot be a DNS label
	 *                                   under virtual-hosted addressing.
	 */
	public function origin( string $bucket ): string {
		return 'https://' . $this->host_for( $bucket );
	}

	/**
	 * Mint a presigned PUT URL for a direct browser-to-storage upload.
	 *
	 * The bytes never pass through PHP, so upload size is bounded by the
	 * storage provider rather than by `post_max_size`.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket          Bucket name.
	 * @param string $key             Object key to create.
	 * @param int    $expires_seconds Validity window. Default 3600.
	 *
	 * @return string Fully-qualified HTTPS URL to PUT to.
	 *
	 * @throws \InvalidArgumentException As presign() does.
	 */
	public function presign_put( string $bucket, string $key, int $expires_seconds = 3600 ): string {
		return $this->presign( Method::PUT, $bucket, $key, array(), $expires_seconds );
	}

	/**
	 * Mint a presigned PUT URL for one part of a multipart upload.
	 *
	 * The client PUTs the chunk and keeps the `ETag` from the response;
	 * those ETags are then passed to
	 * {@see sign_complete_multipart_upload()} to assemble the object.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket          Bucket name.
	 * @param string $key             Object key being assembled.
	 * @param string $upload_id       Upload id from the create call.
	 * @param int    $part_number     1-based part index (1–10000 per the S3 spec).
	 * @param int    $expires_seconds Validity window. Default 3600.
	 *
	 * @return string Fully-qualified HTTPS URL to PUT the chunk to.
	 *
	 * @throws \InvalidArgumentException As presign() does.
	 */
	public function presign_upload_part( string $bucket, string $key, string $upload_id, int $part_number, int $expires_seconds = 3600 ): string {
		return $this->presign(
			Method::PUT,
			$bucket,
			$key,
			array(
				'partNumber' => (string) $part_number,
				'uploadId'   => $upload_id,
			),
			$expires_seconds
		);
	}

	/**
	 * Sign an arbitrary request into the query string.
	 *
	 * The escape hatch behind every `presign_*()` helper. Reach for it
	 * when you need an operation this library doesn't wrap.
	 *
	 * @since 1.0.0
	 *
	 * @param Method                $method          HTTP verb.
	 * @param string                $bucket          Bucket name.
	 * @param string                $key             Object key. '' addresses the bucket itself.
	 * @param array<string, string> $query           Extra query parameters, unencoded.
	 * @param int                   $expires_seconds Validity window. Default 3600.
	 *
	 * @return string Fully-qualified HTTPS URL.
	 *
	 * @throws \InvalidArgumentException On a lifetime outside 1 second to
	 *                                   MAX_EXPIRES, a bucket or key with a
	 *                                   `.` or `..` path segment, or a bucket
	 *                                   that cannot be a DNS label under
	 *                                   virtual-hosted addressing.
	 */
	public function presign( Method $method, string $bucket, string $key = '', array $query = array(), int $expires_seconds = 3600 ): string {
		if ( $expires_seconds < 1 || $expires_seconds > self::MAX_EXPIRES ) {
			throw new \InvalidArgumentException(
				'Presigned URL lifetime must be between 1 and ' . self::MAX_EXPIRES . ' seconds (7 days).'
			);
		}

		[ $amz_date, $date ] = $this->stamp();

		$scope         = $this->scope( $date );
		$host          = $this->host_for( $bucket );
		$canonical_uri = $this->canonical_uri( $bucket, $key );

		$query['X-Amz-Algorithm']     = self::ALGORITHM;
		$query['X-Amz-Credential']    = $this->access_key . '/' . $scope;
		$query['X-Amz-Date']          = $amz_date;
		$query['X-Amz-Expires']       = (string) $expires_seconds;
		$query['X-Amz-SignedHeaders'] = 'host';

		$canonical_query = $this->canonical_query( $query );

		$canonical_request = implode(
			"\n",
			array(
				$method->value,
				$canonical_uri,
				$canonical_query,
				'host:' . $host,
				'',
				'host',
				self::UNSIGNED_PAYLOAD,
			)
		);

		$signature = $this->signature( $this->string_to_sign( $amz_date, $scope, $canonical_request ), $date );

		return 'https://' . $host . $canonical_uri . '?' . $canonical_query . '&X-Amz-Signature=' . $signature;
	}

	/* ─── Signed requests (header signing) ──────────────────────────── */

	/**
	 * Sign a request your own server will execute.
	 *
	 * The returned headers are exhaustive and order-sensitive in the
	 * signature — send them as given. Adding an `x-amz-*` header
	 * afterwards invalidates the signature.
	 *
	 * @since 1.0.0
	 *
	 * @param Method                $method  HTTP verb.
	 * @param string                $bucket  Bucket name.
	 * @param string                $key     Object key. '' addresses the bucket itself.
	 * @param array<string, string> $query   Query parameters, unencoded.
	 * @param string                $payload Raw request body. Hashed in full,
	 *                                       so this is O(body size).
	 * @param array<string, string> $headers Extra headers to sign, e.g.
	 *                                       `['content-type' => 'audio/wav']`.
	 *
	 * @return SignedRequest Ready to hand to any HTTP client.
	 *
	 * @throws \InvalidArgumentException On a header name outside the token
	 *                                   set, a header value with a line
	 *                                   break, a bucket or key with a `.` or
	 *                                   `..` path segment, or a bucket that
	 *                                   cannot be a DNS label under
	 *                                   virtual-hosted addressing.
	 */
	public function sign( Method $method, string $bucket, string $key = '', array $query = array(), string $payload = '', array $headers = array() ): SignedRequest {
		[ $amz_date, $date ] = $this->stamp();

		$scope         = $this->scope( $date );
		$host          = $this->host_for( $bucket );
		$canonical_uri = $this->canonical_uri( $bucket, $key );
		$digest        = hash( 'sha256', $payload );

		// Caller headers first so the mandatory ones below always win.
		$signed = array();

		foreach ( $headers as $name => $value ) {
			$name = strtolower( trim( $name ) );

			// A header name outside the RFC 7230 token set would corrupt
			// the canonical request, and a colon or newline in one is a
			// header-injection attempt.
			if ( 1 !== preg_match( '/^[a-z0-9!#$%&\'*+\-.^_`|~]+$/', $name ) ) {
				throw new \InvalidArgumentException( 'Invalid HTTP header name: ' . $name );
			}

			// CR/LF in a value would split the request when the caller
			// hands these to cURL. Reject rather than silently strip, so
			// a mangled value never gets signed and sent.
			if ( 1 === preg_match( '/[\r\n\x00]/', $value ) ) {
				throw new \InvalidArgumentException( 'Header value for "' . $name . '" contains line breaks.' );
			}

			// SigV4 canonicalisation collapses internal whitespace runs.
			$signed[ $name ] = trim( (string) preg_replace( '/\s+/', ' ', $value ) );
		}

		$signed['host']                 = $host;
		$signed['x-amz-content-sha256'] = $digest;
		$signed['x-amz-date']           = $amz_date;

		ksort( $signed, SORT_STRING );

		$canonical_headers = '';

		foreach ( $signed as $name => $value ) {
			$canonical_headers .= $name . ':' . $value . "\n";
		}

		$signed_headers  = implode( ';', array_keys( $signed ) );
		$canonical_query = array() === $query ? '' : $this->canonical_query( $query );

		$canonical_request = implode(
			"\n",
			array(
				$method->value,
				$canonical_uri,
				$canonical_query,
				$canonical_headers,
				$signed_headers,
				$digest,
			)
		);

		$signature = $this->signature( $this->string_to_sign( $amz_date, $scope, $canonical_request ), $date );

		$signed['Authorization'] = self::ALGORITHM
			. ' Credential=' . $this->access_key . '/' . $scope
			. ', SignedHeaders=' . $signed_headers
			. ', Signature=' . $signature;

		$url = 'https://' . $host . $canonical_uri
			. ( '' === $canonical_query ? '' : '?' . $canonical_query );

		return new SignedRequest( $method, $url, $signed, $payload );
	}

	/**
	 * Sign a server-side object upload.
	 *
	 * Hashing the payload is O(body size), which is fine up to a few
	 * hundred MB. Past that, prefer a presigned PUT or a multipart
	 * upload so the bytes never enter PHP's memory at all.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $key       Object key to create.
	 * @param string $body      Raw object contents.
	 * @param string $mime_type Content-Type to store against the object.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_put_object( string $bucket, string $key, string $body, string $mime_type = 'application/octet-stream' ): SignedRequest {
		return $this->sign( Method::PUT, $bucket, $key, array(), $body, array( 'content-type' => $mime_type ) );
	}

	/**
	 * Sign a server-side copy from one object to another.
	 *
	 * The bytes move inside the storage provider and never pass through
	 * PHP: one request whatever the size. Both buckets must be reachable
	 * with these credentials — for R2, the same account.
	 *
	 * The metadata is replaced rather than copied, which is what lets a copy
	 * published to a public bucket carry long-lived cache headers the
	 * private original never had.
	 *
	 * @since 1.2.0
	 *
	 * @param string $source_bucket Bucket to copy from.
	 * @param string $source_key    Object to copy.
	 * @param string $bucket        Bucket to copy into.
	 * @param string $key           Object to create.
	 * @param string $content_type  Content-Type for the copy.
	 * @param string $cache_control Cache-Control for the copy, or ''.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does, including for the
	 *                                   source bucket and key.
	 */
	public function sign_copy_object(
		string $source_bucket,
		string $source_key,
		string $bucket,
		string $key,
		string $content_type = 'application/octet-stream',
		string $cache_control = ''
	): SignedRequest {
		self::assert_no_dot_segments( $source_bucket );
		self::assert_no_dot_segments( $source_key );

		$headers = array(
			// Each segment encoded, the slashes between them kept: the
			// source is a path, and an encoded slash names a different key.
			'x-amz-copy-source'        => '/' . rawurlencode( $source_bucket ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', ltrim( $source_key, '/' ) ) ) ),
			'x-amz-metadata-directive' => 'REPLACE',
			'content-type'             => $content_type,
		);

		if ( '' !== $cache_control ) {
			$headers['cache-control'] = $cache_control;
		}

		return $this->sign( Method::PUT, $bucket, $key, array(), '', $headers );
	}

	/**
	 * Sign a read of the bucket's CORS configuration.
	 *
	 * A bucket with no configuration answers 404 with a
	 * `NoSuchCORSConfiguration` body rather than an empty 200, so treat that
	 * status as "none set" rather than as a failure.
	 *
	 * @since 1.1.0
	 *
	 * @param string $bucket Bucket name.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_get_bucket_cors( string $bucket ): SignedRequest {
		return $this->sign( Method::GET, $bucket, '', array( 'cors' => '' ) );
	}

	/**
	 * Sign a replacement of the bucket's CORS configuration.
	 *
	 * PutBucketCors replaces the whole configuration; there is no way to add
	 * one rule. Read the current policy first if you mean to keep any of it.
	 *
	 * Content-MD5 is sent because AWS requires it on this call specifically
	 * and refuses the request without it. Other providers ignore it.
	 *
	 * @since 1.1.0
	 *
	 * @param string $bucket Bucket name.
	 * @param Policy $policy The configuration to store.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_put_bucket_cors( string $bucket, Policy $policy ): SignedRequest {
		$body = $policy->to_xml();

		return $this->sign(
			Method::PUT,
			$bucket,
			'',
			array( 'cors' => '' ),
			$body,
			array(
				'content-type' => 'application/xml',
				'content-md5'  => base64_encode( (string) hash( 'md5', $body, true ) ),
			)
		);
	}

	/**
	 * Sign a removal of the bucket's CORS configuration.
	 *
	 * After this the bucket refuses every cross-origin request, so anything
	 * uploading or reading from a browser stops working.
	 *
	 * @since 1.1.0
	 *
	 * @param string $bucket Bucket name.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_delete_bucket_cors( string $bucket ): SignedRequest {
		return $this->sign( Method::DELETE, $bucket, '', array( 'cors' => '' ) );
	}

	/**
	 * Sign an object deletion.
	 *
	 * S3 returns 204 whether or not the key existed, so a success here
	 * is not proof the object was there.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket Bucket name.
	 * @param string $key    Object key to delete.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_delete_object( string $bucket, string $key ): SignedRequest {
		return $this->sign( Method::DELETE, $bucket, $key );
	}

	/**
	 * Sign a metadata-only request for a single object.
	 *
	 * Cheapest way to read size and ETag without transferring the body.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket Bucket name.
	 * @param string $key    Object key.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_head_object( string $bucket, string $key ): SignedRequest {
		return $this->sign( Method::HEAD, $bucket, $key );
	}

	/**
	 * Sign a ListObjectsV2 call.
	 *
	 * Responses are XML and capped at 1000 keys. When the response
	 * carries `<IsTruncated>true</IsTruncated>`, pass its
	 * `<NextContinuationToken>` back in for the following page.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket             Bucket name.
	 * @param int    $max_keys           Page size, clamped to 1–1000.
	 * @param string $prefix             Restrict to keys with this prefix.
	 * @param string $delimiter          Roll keys up into `CommonPrefixes`
	 *                                   at this character. '' disables it.
	 * @param string $continuation_token Token from the previous page.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_list_objects( string $bucket, int $max_keys = 1000, string $prefix = '', string $delimiter = '/', string $continuation_token = '' ): SignedRequest {
		$query = array(
			'list-type' => '2',
			'max-keys'  => (string) max( 1, min( 1000, $max_keys ) ),
		);

		if ( '' !== $prefix ) {
			$query['prefix'] = $prefix;
		}

		if ( '' !== $delimiter ) {
			$query['delimiter'] = $delimiter;
		}

		if ( '' !== $continuation_token ) {
			$query['continuation-token'] = $continuation_token;
		}

		return $this->sign( Method::GET, $bucket, '', $query );
	}

	/**
	 * Sign the start of a multipart upload.
	 *
	 * The response XML carries an `<UploadId>`, which every subsequent
	 * part and the final assembly reference.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $key       Object key being assembled.
	 * @param string $mime_type Content-Type for the finished object.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_create_multipart_upload( string $bucket, string $key, string $mime_type = 'application/octet-stream' ): SignedRequest {
		return $this->sign(
			Method::POST,
			$bucket,
			$key,
			array( 'uploads' => '' ),
			'',
			array( 'content-type' => $mime_type )
		);
	}

	/**
	 * Sign the assembly of a completed multipart upload.
	 *
	 * Parts are sorted by part number and their ETags normalised —
	 * S3 returns ETags already quoted, and double-quoting them is the
	 * usual cause of a `MalformedXML` rejection here.
	 *
	 * @since 1.0.0
	 *
	 * @param string                                     $bucket    Bucket name.
	 * @param string                                     $key       Object key being assembled.
	 * @param string                                     $upload_id Upload id from the create call.
	 * @param array<int, array{PartNumber:int, ETag:string}> $parts Every uploaded part.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException When no parts are supplied, or as
	 *                                   sign() does.
	 */
	public function sign_complete_multipart_upload( string $bucket, string $key, string $upload_id, array $parts ): SignedRequest {
		if ( array() === $parts ) {
			throw new \InvalidArgumentException( 'A multipart upload cannot be completed with zero parts.' );
		}

		usort( $parts, static fn( array $a, array $b ): int => ( (int) $a['PartNumber'] ) <=> ( (int) $b['PartNumber'] ) );

		$xml = '<CompleteMultipartUpload>';

		foreach ( $parts as $part ) {
			$etag = trim( (string) $part['ETag'], '"' );
			$xml .= '<Part>'
				. '<PartNumber>' . (int) $part['PartNumber'] . '</PartNumber>'
				. '<ETag>&quot;' . htmlspecialchars( $etag, ENT_XML1 | ENT_QUOTES, 'UTF-8' ) . '&quot;</ETag>'
				. '</Part>';
		}

		$xml .= '</CompleteMultipartUpload>';

		return $this->sign(
			Method::POST,
			$bucket,
			$key,
			array( 'uploadId' => $upload_id ),
			$xml,
			array( 'content-type' => 'application/xml' )
		);
	}

	/**
	 * Sign the abandonment of a multipart upload.
	 *
	 * Worth calling on failure: unaborted uploads leave parts billing
	 * against the bucket indefinitely.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $key       Object key that was being assembled.
	 * @param string $upload_id Upload id to abandon.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_abort_multipart_upload( string $bucket, string $key, string $upload_id ): SignedRequest {
		return $this->sign( Method::DELETE, $bucket, $key, array( 'uploadId' => $upload_id ) );
	}

	/**
	 * Sign a request for the parts a multipart upload already holds
	 * (ListParts).
	 *
	 * What resuming an upload needs. A browser that reloads halfway through
	 * remembers which parts it sent, but storage decides what counts: a part
	 * the browser saw finish may not have been kept, and one it never heard
	 * back about may have been. The answer is a `ListPartsResult`, paged by
	 * part number.
	 *
	 * @since 1.3.0
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $key       Object key being assembled.
	 * @param string $upload_id Upload id from the create call.
	 * @param int    $max_parts Parts per page, clamped to S3's 1–1,000.
	 * @param int    $marker    List the parts after this part number; 0 for
	 *                          the first page.
	 *
	 * @return SignedRequest
	 *
	 * @throws \InvalidArgumentException As sign() does.
	 */
	public function sign_list_parts( string $bucket, string $key, string $upload_id, int $max_parts = 1000, int $marker = 0 ): SignedRequest {
		$query = array(
			'uploadId'  => $upload_id,
			'max-parts' => (string) max( 1, min( 1000, $max_parts ) ),
		);

		if ( $marker > 0 ) {
			$query['part-number-marker'] = (string) $marker;
		}

		return $this->sign( Method::GET, $bucket, $key, $query );
	}

	/* ─── Helpers ───────────────────────────────────────────────────── */

	/**
	 * Build a `Content-Disposition` value that forces a download under a
	 * chosen filename.
	 *
	 * Delegates to {@see ContentDisposition::attachment()}, which handles
	 * transliteration for non-Latin scripts, Unicode normalisation, bidi
	 * spoofing, and path injection. Kept here as a convenience so callers
	 * with a Signer in hand don't need a second import.
	 *
	 * @since 1.0.0
	 *
	 * @param string $name Desired download filename, any script.
	 *
	 * @return string Complete header value.
	 */
	public static function content_disposition( string $name ): string {
		return ContentDisposition::attachment( $name );
	}

	/**
	 * What var_dump() and print_r() show: everything but the keys.
	 *
	 * `#[\SensitiveParameter]` keeps the keys out of stack traces only. A
	 * signer dumped into a log or onto an error page would otherwise print
	 * the secret in full.
	 *
	 * @since 1.4.0
	 *
	 * @return array{endpoint: string, region: string, addressing: string, timestamp: int|null}
	 */
	public function __debugInfo(): array {
		return array(
			'endpoint'   => $this->endpoint,
			'region'     => $this->region,
			'addressing' => $this->addressing->name,
			'timestamp'  => $this->timestamp,
		);
	}

	/**
	 * Refuse a bucket or key with a `.` or `..` segment.
	 *
	 * S3 keeps a key like `a/../b` literally, but almost nothing between the
	 * signer and the bucket does: browsers, curl, proxies and some gateways
	 * collapse dot segments, and a provider that collapses them after
	 * checking the signature would write or serve a key outside the prefix
	 * the application meant — `uploads/<user>/` + `../<other user>/x`.
	 * Refused here rather than signed.
	 *
	 * @since 1.4.0
	 *
	 * @param string $path Bucket name or object key.
	 *
	 * @return void
	 *
	 * @throws \InvalidArgumentException On a `.` or `..` segment.
	 */
	private static function assert_no_dot_segments( string $path ): void {
		foreach ( explode( '/', $path ) as $segment ) {
			if ( '.' === $segment || '..' === $segment ) {
				throw new \InvalidArgumentException( 'An S3 bucket or key cannot contain a "." or ".." path segment.' );
			}
		}
	}

	/**
	 * Refuse a value that would split a response header.
	 *
	 * @since 1.4.0
	 *
	 * @param string $value Header value.
	 *
	 * @return void
	 *
	 * @throws \InvalidArgumentException On CR, LF or NUL.
	 */
	private static function assert_header_value( string $value ): void {
		if ( 1 === preg_match( '/[\r\n\x00]/', $value ) ) {
			throw new \InvalidArgumentException( 'A header value cannot contain a line break.' );
		}
	}

	/**
	 * Current signing timestamps as `[ amz_date, date ]`.
	 *
	 * @since 1.0.0
	 *
	 * @return array{0: string, 1: string} ISO basic timestamp and YYYYMMDD.
	 */
	private function stamp(): array {
		$amz_date = gmdate( 'Ymd\THis\Z', $this->timestamp ?? time() );

		return array( $amz_date, substr( $amz_date, 0, 8 ) );
	}

	/**
	 * Credential scope for a given signing date.
	 *
	 * @since 1.0.0
	 *
	 * @param string $date YYYYMMDD.
	 *
	 * @return string
	 */
	private function scope( string $date ): string {
		return $date . '/' . $this->region . '/' . self::SERVICE . '/aws4_request';
	}

	/**
	 * Strip a scheme, path, and trailing slash from a configured endpoint.
	 *
	 * Callers reasonably paste `https://host/` from a dashboard. Signing
	 * that verbatim produces a `Host` header of `https://host/`, which
	 * fails with an unhelpful signature error rather than a clear one.
	 *
	 * @since 1.0.0
	 *
	 * @param string $endpoint Raw endpoint.
	 *
	 * @return string Bare host, optionally with a port.
	 *
	 * @throws \InvalidArgumentException When nothing usable remains.
	 */
	private static function normalize_endpoint( string $endpoint ): string {
		$host = trim( $endpoint );
		$host = (string) preg_replace( '#^[a-z][a-z0-9+.\-]*://#i', '', $host );
		$host = explode( '/', $host, 2 )[0];
		$host = rtrim( $host, '.' );

		if ( '' === $host || 1 !== preg_match( '/^[A-Za-z0-9.\-]+(:\d{1,5})?$/', $host ) ) {
			throw new \InvalidArgumentException( 'S3 endpoint must be a bare host, e.g. "s3.eu-west-2.amazonaws.com".' );
		}

		return strtolower( $host );
	}

	/**
	 * The `Host` header for a request against a given bucket.
	 *
	 * Under virtual-hosted addressing the bucket becomes a DNS label, so
	 * it is validated here — an incompatible name would otherwise be
	 * signed into a hostname that cannot resolve or whose certificate
	 * will not match.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket Bucket name.
	 *
	 * @return string
	 *
	 * @throws \InvalidArgumentException When the bucket cannot be a DNS label.
	 */
	private function host_for( string $bucket ): string {
		if ( AddressingStyle::Path === $this->addressing ) {
			return $this->endpoint;
		}

		if ( ! AddressingStyle::is_dns_compatible( $bucket ) ) {
			throw new \InvalidArgumentException(
				'Bucket "' . $bucket . '" cannot be used with virtual-hosted addressing: '
				. 'it must be 3-63 characters of lowercase letters, digits and hyphens, with no dots.'
			);
		}

		return $bucket . '.' . $this->endpoint;
	}

	/**
	 * Canonical resource path for a bucket and optional key.
	 *
	 * Under virtual-hosted addressing the bucket lives in the hostname,
	 * so it must NOT appear in the path as well.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bucket Bucket name.
	 * @param string $key    Object key, or '' for the bucket itself.
	 *
	 * @return string
	 *
	 * @throws \InvalidArgumentException On a `.` or `..` path segment.
	 */
	private function canonical_uri( string $bucket, string $key ): string {
		self::assert_no_dot_segments( $bucket );
		self::assert_no_dot_segments( $key );

		if ( AddressingStyle::VirtualHosted === $this->addressing ) {
			return '' === $key ? '/' : '/' . $this->encode_key( $key );
		}

		$uri = '/' . rawurlencode( $bucket );

		if ( '' !== $key ) {
			$uri .= '/' . $this->encode_key( $key );
		}

		return $uri;
	}

	/**
	 * Encode an object key for the canonical URI.
	 *
	 * Percent-encodes everything, then restores `/` so multi-segment
	 * keys keep their hierarchy.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key Raw object key. A leading slash is dropped.
	 *
	 * @return string
	 */
	private function encode_key( string $key ): string {
		return str_replace( '%2F', '/', rawurlencode( ltrim( $key, '/' ) ) );
	}

	/**
	 * Canonical query string: sorted by name, RFC 3986 encoded.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, string> $query Unencoded parameters.
	 *
	 * @return string
	 */
	private function canonical_query( array $query ): string {
		$pairs = array();

		foreach ( $query as $name => $value ) {
			$pairs[ rawurlencode( (string) $name ) ] = rawurlencode( $value );
		}

		// SigV4 sorts by the encoded name, byte by byte. A plain ksort()
		// compares numeric-looking names as numbers.
		ksort( $pairs, SORT_STRING );

		$out = array();

		foreach ( $pairs as $name => $value ) {
			$out[] = $name . '=' . $value;
		}

		return implode( '&', $out );
	}

	/**
	 * Assemble the string-to-sign from a canonical request.
	 *
	 * @since 1.0.0
	 *
	 * @param string $amz_date          ISO basic timestamp.
	 * @param string $scope             Credential scope.
	 * @param string $canonical_request The canonical request.
	 *
	 * @return string
	 */
	private function string_to_sign( string $amz_date, string $scope, string $canonical_request ): string {
		return implode(
			"\n",
			array(
				self::ALGORITHM,
				$amz_date,
				$scope,
				hash( 'sha256', $canonical_request ),
			)
		);
	}

	/**
	 * Sign a string-to-sign with the derived key.
	 *
	 * @since 1.0.0
	 *
	 * @param string $string_to_sign The string to sign.
	 * @param string $date           YYYYMMDD of the signing key.
	 *
	 * @return string Lowercase hex signature.
	 */
	private function signature( string $string_to_sign, string $date ): string {
		return hash_hmac( 'sha256', $string_to_sign, $this->signing_key( $date ) );
	}

	/**
	 * Derive the date/region/service scoped signing key.
	 *
	 * Four chained HMACs, per the SigV4 spec. Returns raw bytes.
	 *
	 * @since 1.0.0
	 *
	 * @param string $date YYYYMMDD.
	 *
	 * @return string 32 raw bytes.
	 */
	private function signing_key( string $date ): string {
		$k = hash_hmac( 'sha256', $date, 'AWS4' . $this->secret_key, true );
		$k = hash_hmac( 'sha256', $this->region, $k, true );
		$k = hash_hmac( 'sha256', self::SERVICE, $k, true );

		return hash_hmac( 'sha256', 'aws4_request', $k, true );
	}
}
