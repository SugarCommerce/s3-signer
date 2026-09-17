# S3 Signer

AWS Signature Version 4 signing for S3-compatible object storage. Presigned URLs and signed request headers — no HTTP client, no SDK, no dependencies. Point it at Cloudflare R2, AWS S3, Backblaze B2, DigitalOcean Spaces, MinIO, or anything else speaking the same protocol.

The AWS SDK is ~15MB and pulls in Guzzle. If all you need is "give this customer a 60-second download link", this is 4 files.

## Features

- 🔗 **Presigned URLs** — GET, PUT, and multipart upload parts. Hand them to a browser; bytes never pass through PHP.
- ✍️ **Signed requests** — `SignedRequest` objects carrying URL, method and headers for calls your server makes. Use any HTTP client.
- 🌍 **Internationalised filenames** — `Content-Disposition` that works in every script. `音乐样本包.wav` downloads correctly, and its ASCII fallback reads `yin le yang ben bao.wav` rather than `_____.wav`.
- 🛡️ **Filename hardening** — path traversal, bidi display-spoofing, zero-width characters, header injection and quote-escaping all handled.
- 📦 **Multipart uploads** — create, sign parts, complete, abort. Part sorting and ETag normalisation included.
- 🔓 **Bucket CORS** — read, write and *check* the policy. `supports_multipart_upload()` answers the question a deploy actually needs: will a browser upload from this origin work?
- 🧾 **Download naming** — rename a file at download time without touching the stored object.
- 🚫 **Zero dependencies** — plain PHP. `ext-intl` is optional and only sharpens transliteration.
- ⚡ **No I/O** — pure functions over credentials. Nothing to mock in your tests.

## Providers

```php
use SugarCommerce\S3Signer\Provider;

Provider::options();   // value => label, for a settings dropdown

$signer = Provider::Linode->signer( $key, $secret, region: 'eu-central-1' );
$signer = Provider::R2->signer( $key, $secret, account_id: $account );
$signer = Provider::MinIO->signer( $key, $secret, endpoint: 'minio.local:9000' );
```

| Provider | Endpoint | Addressing |
|---|---|---|
| Amazon S3 | `s3.{region}.amazonaws.com` | virtual-hosted |
| Cloudflare R2 | `{account}.r2.cloudflarestorage.com` | path |
| Backblaze B2 | `s3.{region}.backblazeb2.com` | virtual-hosted |
| DigitalOcean Spaces | `{region}.digitaloceanspaces.com` | virtual-hosted |
| Linode Object Storage | `{region}.linodeobjects.com` | virtual-hosted |
| Wasabi | `s3.{region}.wasabisys.com` | virtual-hosted |
| Scaleway | `s3.{region}.scw.cloud` | virtual-hosted |
| MinIO / other | you supply it | path |

Three things vary between providers and all three fail confusingly when guessed:

**Addressing style.** Virtual-hosted puts the bucket in the hostname, path style puts it in the path. Get it wrong and every request 404s against a bucket that plainly exists.

**Region.** R2 signs everything as `auto` and rejects a real region; AWS rejects a signature computed for the wrong one.

**What identifies the endpoint.** Most interpolate a region, R2 an account id, MinIO is whatever the operator hosts. `needs_account_id()` and `needs_endpoint()` let a form show only the fields that apply.

`us-east-1` on AWS deliberately yields the legacy global `s3.amazonaws.com` rather than `s3.us-east-1.amazonaws.com`, because that is what the region resolves to.

## Requirements

- PHP 8.5+
- `ext-intl` (optional — improves non-Latin transliteration)

## Installation

```bash
composer require sugarcommerce/s3-signer
```

## Usage

### Presigned download link

```php
use SugarCommerce\S3Signer\Signer;

$signer = new Signer(
    access_key: getenv( 'R2_ACCESS_KEY' ),
    secret_key: getenv( 'R2_SECRET_KEY' ),
    endpoint:   '<account>.r2.cloudflarestorage.com',
);

$url = $signer->presign_get( 'my-bucket', 'files/8a3f2c.zip', 60 );
```

### Renaming the file at download time

Store opaque keys, deliver meaningful names. The object is untouched — S3 and R2 both honour `response-content-disposition` on a presigned GET.

```php
$url = $signer->presign_get(
    'my-bucket',
    'files/8a3f2c.zip',
    60,
    'Drum Kit Vol. 2.zip'
);
```

### Direct browser uploads

```php
$url = $signer->presign_put( 'my-bucket', 'uploads/new.wav', 3600 );
```

The browser `PUT`s straight to storage, so upload size is bounded by your provider rather than by `post_max_size`.

### Requests your server makes

`sign_*()` returns a `SignedRequest`. Send it however you like:

```php
$request = $signer->sign_delete_object( 'my-bucket', 'files/old.zip' );

$ch = curl_init( $request->url );
curl_setopt_array( $ch, [
    CURLOPT_CUSTOMREQUEST  => $request->method->value,
    CURLOPT_HTTPHEADER     => $request->curl_headers(),
    CURLOPT_RETURNTRANSFER => true,
] );
$response = curl_exec( $ch );
```

Available: `sign_put_object()`, `sign_delete_object()`, `sign_head_object()`, `sign_list_objects()`, `sign_create_multipart_upload()`, `sign_complete_multipart_upload()`, `sign_abort_multipart_upload()`.

> The returned headers are exhaustive and the signature covers exactly that set. Send them as given — one extra `x-amz-*` header invalidates the signature.

### Multipart upload

```php
// 1. Start it (your server)
$request = $signer->sign_create_multipart_upload( 'my-bucket', 'big/file.zip' );
// → execute, parse <UploadId> from the XML response

// 2. Sign each chunk (browser PUTs these, keeping each ETag)
$url = $signer->presign_upload_part( 'my-bucket', 'big/file.zip', $upload_id, $part_number );

// 3. Assemble (your server)
$request = $signer->sign_complete_multipart_upload( 'my-bucket', 'big/file.zip', $upload_id, [
    [ 'PartNumber' => 1, 'ETag' => '"abc…"' ],
    [ 'PartNumber' => 2, 'ETag' => '"def…"' ],
] );
```

Parts are sorted and ETags normalised for you — double-quoted ETags are the usual cause of a `MalformedXML` rejection here.

### Filenames

`ContentDisposition` is usable on its own:

```php
use SugarCommerce\S3Signer\ContentDisposition;

ContentDisposition::attachment( 'Naïve Café — Master.wav' );
// attachment; filename="Naive Cafe - Master.wav";
//   filename*=UTF-8''Na%C3%AFve%20Caf%C3%A9%20%E2%80%94%20Master.wav
```

RFC 6266 wants two forms. `filename*` carries the real name and is what current browsers use; `filename` is the ASCII fallback, and it's where most implementations fall down by blanking every non-ASCII byte. Here it's transliterated:

| Input | ASCII fallback |
|---|---|
| `naïve café.mp3` | `naive cafe.mp3` |
| `Übungsstück für Klavier.wav` | `Ubungsstuck fur Klavier.wav` |
| `日本語のファイル.zip` | `ri ben yunofairu.zip` |
| `音乐样本包.wav` | `yin le yang ben bao.wav` |
| `한국어 파일.mp3` | `hangug-eo pail.mp3` |
| `Русский файл.pdf` | `Russkij fajl.pdf` |
| `Ελληνικά.txt` | `Ellenika.txt` |
| `🎵🎹🥁.wav` | `download.wav` |

It also handles the failure modes that bite in production:

- **Unicode form.** macOS supplies decomposed (NFD) filenames, so `café` arrives as `e` plus a combining acute and percent-encodes into something Windows renders wrongly. Normalised to NFC.
- **Bidi spoofing.** A right-to-left override makes `invoice<U+202E>gpj.exe` display as `invoiceexe.jpg`. Stripped.
- **Path injection.** `../../etc/passwd` becomes `passwd`.
- **Header injection.** Newlines and quotes that would terminate the header early are removed.
- **Length.** Clamped to 200 bytes without splitting a multibyte character or losing the extension.

### Providers

Use a factory and the endpoint, region and addressing style are set for you:

```php
Signer::r2( $key, $secret, $account_id );            // <account>.r2.cloudflarestorage.com
Signer::aws( $key, $secret, 'eu-west-2' );
Signer::backblaze( $key, $secret, 'us-west-004' );
Signer::digitalocean( $key, $secret, 'ams3' );
Signer::minio( $key, $secret, 'localhost:9000' );
```

### Addressing style

Providers disagree about where the bucket name belongs, and it isn't cosmetic — the choice changes both the `Host` header and the canonical URI, so signing one way and requesting the other fails with an opaque `SignatureDoesNotMatch`.

```
Path            https://endpoint/bucket/key
Virtual-hosted  https://bucket.endpoint/key
```

| Provider | Style |
|---|---|
| Cloudflare R2 | Path, against the account endpoint |
| AWS S3 | Virtual-hosted (path-style is deprecated for newer buckets) |
| Backblaze B2 | Virtual-hosted |
| DigitalOcean Spaces | Virtual-hosted |
| MinIO / Ceph | Path |

Constructing directly, it's the sixth argument and defaults to path-style:

```php
$signer = new Signer(
    $key, $secret, 's3.eu-west-2.amazonaws.com', 'eu-west-2',
    addressing: AddressingStyle::VirtualHosted,
);
```

Virtual-hosted addressing puts the bucket into a hostname, so bucket names are validated as DNS labels — an uppercase, underscored or dotted bucket is rejected rather than signed into a host that can't resolve or whose certificate won't match.

### Deterministic signing

Pass a fixed `timestamp` to make signatures reproducible in tests. Leave it null in production or every signature shares one eventually-expired date.

```php
$signer = new Signer( $key, $secret, $endpoint, 'auto', timestamp: 1700000000 );
```

### Bucket CORS

Direct-to-browser uploads need a CORS policy on the bucket, and it is the
setting people get wrong — usually not by leaving it off, which fails loudly,
but by writing a rule that looks complete and is missing one line.

```php
use SugarCommerce\S3Signer\Cors\{Policy, Rule};

$policy = Policy::for_browser_uploads( [ 'https://app.example.com' ] );

$request = $signer->sign_put_bucket_cors( 'my-bucket', $policy );
// PUT it with your HTTP client of choice.
```

Read the current one back, and ask it the question that matters:

```php
$request = $signer->sign_get_bucket_cors( 'my-bucket' );
// GET it, then:
$policy = Policy::from_xml( $body );   // '' or a 404 body is an empty policy

$result = $policy->supports_multipart_upload( 'https://app.example.com' );

$result['ok'];      // false
$result['reason'];  // 'PUT is allowed but ETag is not exposed, so parts
                    //  upload and the upload then fails at assembly.'
```

That is the failure worth naming. A multipart upload works like this: the
browser PUTs each part, storage answers with that part's ETag, and the browser
sends every ETag back to assemble the object. If the rule does not **expose**
ETag, every part uploads successfully, the browser cannot read a single one of
them, and the upload fails at the last step with an error that mentions neither
CORS nor ETag. `Rule::browser_upload()` exists so you cannot write that rule by
accident.

Two more traps the types close:

- S3 does no subdomain matching. `https://*.example.com` matches **nothing**.
- `*` in `ExposeHeaders` is not honoured everywhere — S3 accepts it, R2
  historically did not. Name the headers.

`PutBucketCors` replaces the whole configuration; there is no way to add one
rule. Read the current policy first if you mean to keep any of it.

## Testing

```bash
composer install
composer test
```

69 tests. The signature vectors are golden values verified byte-for-byte against a signer that has been serving production R2 downloads — a change to any of them means every presigned URL your application has issued would stop working.

## License

GPL-2.0-or-later
