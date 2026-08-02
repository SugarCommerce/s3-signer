<?php
/**
 * ContentDisposition test suite.
 *
 * The transliteration cases are deliberately exhaustive across scripts.
 * A filename is the one piece of a download the customer actually reads,
 * and getting it wrong for anyone outside Latin-1 is the sort of bug
 * that never gets reported — the buyer just assumes the file is broken.
 *
 * @package   Sugar\S3Signer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace Sugar\S3Signer\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Sugar\S3Signer\ContentDisposition;

final class ContentDispositionTest extends TestCase {

	/**
	 * Pull the ASCII `filename` value out of a header string.
	 */
	private function ascii_of( string $filename ): string {
		preg_match( '/filename="([^"]*)"/', ContentDisposition::attachment( $filename ), $m );

		return $m[1] ?? '';
	}

	/**
	 * Pull the percent-encoded `filename*` value out of a header string.
	 */
	private function utf8_of( string $filename ): string {
		preg_match( "/filename\*=UTF-8''(.*)$/", ContentDisposition::attachment( $filename ), $m );

		return $m[1] ?? '';
	}

	/* ─── Header shape ──────────────────────────────────────────────── */

	public function test_emits_both_rfc_6266_forms(): void {
		$this->assertSame(
			'attachment; filename="report.pdf"; filename*=UTF-8\'\'report.pdf',
			ContentDisposition::attachment( 'report.pdf' )
		);
	}

	public function test_the_utf8_form_always_round_trips_to_the_sanitised_name(): void {
		$name = 'Naïve Café — Master.wav';

		$this->assertSame(
			ContentDisposition::sanitize( $name ),
			rawurldecode( $this->utf8_of( $name ) )
		);
	}

	/* ─── Transliteration across scripts ────────────────────────────── */

	#[RequiresPhpExtension( 'intl' )]
	#[DataProvider( 'scripts' )]
	public function test_non_latin_scripts_transliterate_to_readable_ascii( string $input, string $expected ): void {
		$this->assertSame( $expected, $this->ascii_of( $input ) );
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function scripts(): array {
		return array(
			'french accents'   => array( 'naïve café.mp3', 'naive cafe.mp3' ),
			'german umlauts'   => array( 'Übungsstück für Klavier.wav', 'Ubungsstuck fur Klavier.wav' ),
			'spanish tilde'    => array( 'Canción Niña.flac', 'Cancion Nina.flac' ),
			'japanese'         => array( '日本語のファイル.zip', 'ri ben yunofairu.zip' ),
			'chinese'          => array( '音乐样本包.wav', 'yin le yang ben bao.wav' ),
			'korean'           => array( '한국어 파일.mp3', 'hangug-eo pail.mp3' ),
			'cyrillic'         => array( 'Русский файл.pdf', 'Russkij fajl.pdf' ),
			'greek'            => array( 'Ελληνικά.txt', 'Ellenika.txt' ),
		);
	}

	/**
	 * Latin-1 accents must survive even without ext-intl, since iconv
	 * handles them. Non-Latin scripts degrade gracefully instead.
	 */
	public function test_accented_latin_never_becomes_underscores(): void {
		$this->assertStringNotContainsString( '_', $this->ascii_of( 'café.mp3' ) );
	}

	public function test_a_fully_transliterated_away_name_keeps_its_extension(): void {
		$this->assertSame( 'download.wav', $this->ascii_of( '🎵🎹🥁.wav' ) );
	}

	public function test_emoji_among_readable_text_does_not_destroy_the_name(): void {
		$this->assertSame( 'Drum Kit _ Vol.2.zip', $this->ascii_of( 'Drum Kit 🥁 Vol.2.zip' ) );
	}

	public function test_underscore_runs_are_collapsed(): void {
		$this->assertStringNotContainsString( '__', $this->ascii_of( '🎵🎹🥁 kit 🎺🎷.wav' ) );
	}

	/* ─── Unicode normalisation ─────────────────────────────────────── */

	#[RequiresPhpExtension( 'intl' )]
	public function test_decomposed_macos_filenames_are_normalised_to_nfc(): void {
		$decomposed = "cafe\u{0301}.wav";   // 'e' + combining acute, as macOS supplies
		$composed   = "caf\u{00E9}.wav";    // single precomposed 'é'

		$this->assertSame(
			ContentDisposition::attachment( $composed ),
			ContentDisposition::attachment( $decomposed )
		);
		$this->assertSame( 'caf%C3%A9.wav', $this->utf8_of( $decomposed ) );
	}

	/* ─── Security ──────────────────────────────────────────────────── */

	public function test_bidi_override_characters_are_stripped(): void {
		// Without stripping, this displays to the user as "invoice.jpg".
		$this->assertSame( 'invoicegpj.exe', $this->ascii_of( "invoice\u{202E}gpj.exe" ) );
		$this->assertStringNotContainsString( '%E2%80%AE', $this->utf8_of( "invoice\u{202E}gpj.exe" ) );
	}

	public function test_zero_width_characters_are_stripped(): void {
		$this->assertSame( 'hello.zip', $this->ascii_of( "he\u{200B}llo.zip" ) );
	}

	public function test_byte_order_marks_are_stripped(): void {
		$this->assertSame( 'file.zip', $this->ascii_of( "\u{FEFF}file.zip" ) );
	}

	#[DataProvider( 'path_injections' )]
	public function test_directory_components_are_removed( string $input, string $expected ): void {
		$this->assertSame( $expected, $this->ascii_of( $input ) );
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function path_injections(): array {
		return array(
			'unix traversal'  => array( '../../etc/passwd', 'passwd' ),
			'absolute unix'   => array( '/var/www/secret.env', 'secret.env' ),
			'windows path'    => array( 'C:\\Users\\dave\\file.zip', 'file.zip' ),
			'mixed separator' => array( 'a/b\\c/file.txt', 'file.txt' ),
		);
	}

	public function test_quotes_that_would_terminate_the_header_are_removed(): void {
		$value = ContentDisposition::attachment( 'evil"; filename="pwned.exe' );

		$this->assertSame( 1, substr_count( $value, 'filename="' ) );
		$this->assertStringNotContainsString( 'pwned.exe"', $this->ascii_of( 'evil"; filename="pwned.exe' ) );
	}

	public function test_backslashes_are_removed_from_the_quoted_string(): void {
		$this->assertStringNotContainsString( '\\', $this->ascii_of( 'a\\"b.zip' ) );
	}

	public function test_control_characters_are_stripped(): void {
		$this->assertSame( 'abc.zip', $this->ascii_of( "a\x00b\x1Fc.zip" ) );
	}

	public function test_newlines_cannot_inject_a_second_header(): void {
		$value = ContentDisposition::attachment( "file.zip\r\nX-Injected: yes" );

		$this->assertStringNotContainsString( "\r", $value );
		$this->assertStringNotContainsString( "\n", $value );
	}

	/* ─── Degenerate input ──────────────────────────────────────────── */

	#[DataProvider( 'degenerate' )]
	public function test_unusable_names_fall_back_safely( string $input ): void {
		$this->assertSame( 'download', $this->ascii_of( $input ) );
	}

	/** @return array<string, array{0: string}> */
	public static function degenerate(): array {
		return array(
			'empty'      => array( '' ),
			'slash'      => array( '/' ),
			'dots'       => array( '...' ),
			'spaces'     => array( '   ' ),
			'dot slash'  => array( './' ),
		);
	}

	public function test_invalid_utf8_does_not_throw(): void {
		$value = ContentDisposition::attachment( "bad\xC3\x28name.zip" );

		$this->assertStringStartsWith( 'attachment; filename="', $value );
	}

	/* ─── Length ────────────────────────────────────────────────────── */

	public function test_long_names_are_clamped_but_keep_their_extension(): void {
		$name      = str_repeat( 'ünïcödé-', 40 ) . '.wav';
		$sanitized = ContentDisposition::sanitize( $name );

		$this->assertLessThanOrEqual( 200, strlen( $sanitized ) );
		$this->assertStringEndsWith( '.wav', $sanitized );
	}

	public function test_clamping_never_splits_a_multibyte_character(): void {
		$sanitized = ContentDisposition::sanitize( str_repeat( '日', 300 ) . '.zip' );

		$this->assertTrue( mb_check_encoding( $sanitized, 'UTF-8' ) );
	}

	public function test_short_names_are_left_alone(): void {
		$this->assertSame( 'track 01.wav', ContentDisposition::sanitize( 'track 01.wav' ) );
	}

	/* ─── Whitespace ────────────────────────────────────────────────── */

	public function test_whitespace_runs_are_collapsed(): void {
		$this->assertSame( 'a b.zip', ContentDisposition::sanitize( "a  \t b.zip" ) );
	}

	public function test_non_breaking_spaces_are_normalised(): void {
		$this->assertSame( 'a b.zip', ContentDisposition::sanitize( "a\u{00A0}b.zip" ) );
	}
}
