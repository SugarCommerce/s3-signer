<?php
declare( strict_types=1 );
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../../bench-lib.php';

use SugarMill\S3Signer\Signer;

$signer = Signer::r2( 'AKIAEXAMPLE', str_repeat( 'k', 40 ), 'account123' );

echo "s3-signer\n";
bench( 'presign_get', 50000, static fn() => $signer->presign_get( 'bucket', 'files/a.zip', 60 ) );
bench( 'presign_get + filename', 20000, static fn() => $signer->presign_get( 'bucket', 'files/a.zip', 60, 'Naïve Café.wav' ) );
bench( 'presign_upload_part', 50000, static fn() => $signer->presign_upload_part( 'bucket', 'big.zip', 'UP-1', 7 ) );
bench( 'sign_delete_object', 50000, static fn() => $signer->sign_delete_object( 'bucket', 'files/a.zip' ) );
bench( 'sign_list_objects', 50000, static fn() => $signer->sign_list_objects( 'bucket', 1000, 'p/' ) );
bench_footer();
