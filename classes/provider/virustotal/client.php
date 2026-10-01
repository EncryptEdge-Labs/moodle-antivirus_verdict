<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * VirusTotal API v3 client.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\provider\virustotal;

use core\http_client;
use GuzzleHttp\Exception\GuzzleException;
use antivirus_verdict\local\config_credentials;
use antivirus_verdict\local\credential_provider;
use antivirus_verdict\local\provider_health;
use antivirus_verdict\local\retry_policy;
use antivirus_verdict\provider\analysis_result;
use antivirus_verdict\provider\connection_result;
use antivirus_verdict\provider\file_lookup_result;
use antivirus_verdict\provider\file_payload;
use antivirus_verdict\provider\malware_provider;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\provider\submission_result;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\ResponseInterface;


/**
 * Isolated VirusTotal API v3 transport. Does not apply Moodle scan policy.
 *
 * Callers must not pass user-controlled URLs. All endpoints are constructed
 * internally. The API key is attached only as the x-apikey request header.
 */
class client implements malware_provider {
    /** Official VirusTotal API v3 base URL. */
    public const BASE_URI = 'https://www.virustotal.com/api/v3';

    /**
     * Documented direct-upload limit for POST /files.
     *
     * @see https://docs.virustotal.com/reference/files-scan
     */
    public const DIRECT_UPLOAD_MAX_BYTES = 33554432;

    /**
     * Documented maximum for the upload-url flow.
     *
     * @see https://docs.virustotal.com/reference/files-upload-url
     */
    public const LARGE_UPLOAD_MAX_BYTES = 681574400;

    /**
     * Empty-file SHA-256 used only for credential testing (GET /files/{hash}).
     *
     * A 200 or 404 both prove the key was accepted. The key is never placed
     * in the URL (unlike GET /users/{apikey}).
     */
    public const CONNECTION_TEST_SHA256 =
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    /** GET request timeout in seconds. */
    public const TIMEOUT_GET = 20;

    /** Upload request timeout in seconds. */
    public const TIMEOUT_UPLOAD = 60;

    /** TCP connect timeout in seconds. */
    public const TIMEOUT_CONNECT = 10;

    /** @var credential_provider Trusted server-side credentials. */
    private credential_provider $credentials;

    /** @var http_client Moodle HTTP client (Guzzle). */
    private http_client $http;

    /** @var provider_health Site-wide VirusTotal availability circuit. */
    private provider_health $health;

    /**
     * Create a VirusTotal API v3 client.
     *
     * @param credential_provider $credentials Trusted server-side credentials.
     * @param http_client $http Moodle HTTP client (Guzzle).
     * @param provider_health|null $health Availability circuit.
     */
    public function __construct(
        credential_provider $credentials,
        http_client $http,
        ?provider_health $health = null
    ) {
        $this->credentials = $credentials;
        $this->http = $http;
        $this->health = $health ?? new provider_health();
    }

    /**
     * Build a production client from site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(
            new config_credentials(),
            new http_client(self::default_http_options())
        );
    }

    /**
     * Default Moodle HTTP client options for VirusTotal.
     *
     * @return array
     */
    public static function default_http_options(): array {
        return [
            'timeout' => self::TIMEOUT_GET,
            'connect_timeout' => self::TIMEOUT_CONNECT,
            'http_errors' => false,
        ];
    }

    /**
     * Verify credentials with a hash lookup that does not upload a file.
     *
     * @return connection_result
     */
    public function test_connection(): connection_result {
        try {
            $response = $this->request(
                'GET',
                'files/' . self::CONNECTION_TEST_SHA256,
                ['timeout' => self::TIMEOUT_GET],
                true
            );
        } catch (provider_exception $e) {
            return new connection_result(false, $e->errorcode);
        }

        $status = $response->getStatusCode();
        if ($status === 200 || $status === 404) {
            return new connection_result(true, 'connection_success');
        }
        if ($status === 429) {
            return new connection_result(false, 'error_ratelimit');
        }

        try {
            $this->throw_for_status($response, false);
        } catch (provider_exception $e) {
            return new connection_result(false, $e->errorcode);
        }

        return new connection_result(false, 'error_generic');
    }

    /**
     * Look up a file object by SHA-256.
     *
     * @param string $sha256 Hex SHA-256.
     * @return file_lookup_result
     */
    public function lookup_file_hash(string $sha256): file_lookup_result {
        $sha256 = strtolower($sha256);
        $this->assert_sha256($sha256);

        $response = $this->request('GET', 'files/' . $sha256, ['timeout' => self::TIMEOUT_GET]);
        $status = $response->getStatusCode();
        if ($status === 404) {
            return file_lookup_result::not_found($sha256);
        }

        $data = $this->require_success_data($response);
        $id = $this->optional_string($data, 'id') ?? $sha256;
        $attributes = $this->optional_array($data, 'attributes') ?? [];
        $stats = $this->normalise_stats($attributes['last_analysis_stats'] ?? null);
        if ($stats === null) {
            $stats = $this->stats_from_analysis_results($attributes['last_analysis_results'] ?? null);
        }
        $analysistime = $this->optional_int($attributes, 'last_analysis_date');
        $name = $this->optional_string($attributes, 'meaningful_name');
        $reportedsha = $this->optional_string($attributes, 'sha256') ?? $id;

        return new file_lookup_result(true, $reportedsha, $stats, $analysistime, $name);
    }

    /**
     * Upload file content for analysis.
     *
     * Files larger than the documented POST /files limit use GET /files/upload_url
     * and then POST to that VirusTotal-issued URL after host validation.
     *
     * @param file_payload $file File payload.
     * @return submission_result
     */
    public function upload_file(file_payload $file): submission_result {
        if ($file->size > $this->get_large_upload_max()) {
            throw new provider_exception('error_filetoolarge', '', 413);
        }

        $uploadurl = null;
        if ($file->size > $this->get_direct_upload_max()) {
            $uploadurl = $this->get_large_file_upload_url();
        }

        $options = [
            'timeout' => self::TIMEOUT_UPLOAD,
            'multipart' => [[
                'name' => 'file',
                'contents' => $file->contents,
                'filename' => $file->filename,
            ]],
        ];

        if ($uploadurl === null) {
            $response = $this->request('POST', 'files', $options);
            $data = $this->require_success_data($response);
        } else {
            try {
                $response = $this->request_absolute('POST', $uploadurl, $options);
                $data = $this->require_success_data($response);
            } catch (provider_exception $e) {
                if (in_array($e->errorcode, ['error_network', 'error_server', 'error_ratelimit', 'error_generic'], true)) {
                    throw new provider_exception(
                        'error_uploadinterrupted',
                        $e->debuginfo,
                        $e->httpstatus,
                        $e->retryafter
                    );
                }
                throw $e;
            }
        }
        $analysisid = $this->optional_string($data, 'id');
        if ($analysisid === null || $analysisid === '') {
            throw new provider_exception('error_malformed');
        }

        return new submission_result($analysisid);
    }

    /**
     * Retrieve an analysis object.
     *
     * @param string $analysisid Analysis identifier.
     * @return analysis_result
     */
    public function get_analysis(string $analysisid): analysis_result {
        $this->assert_analysis_id($analysisid);
        $response = $this->request(
            'GET',
            'analyses/' . rawurlencode($analysisid),
            ['timeout' => self::TIMEOUT_GET]
        );
        $data = $this->require_success_data($response);
        $id = $this->optional_string($data, 'id') ?? $analysisid;
        $attributes = $this->optional_array($data, 'attributes') ?? [];
        $status = $this->optional_string($attributes, 'status') ?? '';
        if ($status === '') {
            throw new provider_exception('error_malformed');
        }
        $stats = $this->normalise_stats($attributes['stats'] ?? null);

        return new analysis_result($id, $status, $stats);
    }

    /**
     * GET /files/upload_url and return a validated VirusTotal upload URL.
     *
     * The response data is a URL string rather than an object, so this uses
     * require_success_body() instead of require_success_data() while keeping
     * the same status-before-body error classification.
     *
     * @return string
     */
    protected function get_large_file_upload_url(): string {
        $response = $this->request('GET', 'files/upload_url', ['timeout' => self::TIMEOUT_GET]);
        $decoded = $this->require_success_body($response, false);
        $url = $decoded['data'] ?? null;
        if (!is_string($url) || $url === '') {
            throw new provider_exception('error_malformed');
        }
        $this->assert_virustotal_upload_url($url);
        return $url;
    }

    /**
     * Documented POST /files size limit.
     *
     * @return int
     */
    protected function get_direct_upload_max(): int {
        return self::DIRECT_UPLOAD_MAX_BYTES;
    }

    /**
     * Documented upload-url size limit.
     *
     * @return int
     */
    protected function get_large_upload_max(): int {
        return self::LARGE_UPLOAD_MAX_BYTES;
    }

    /**
     * Send an authenticated request to a relative API v3 path.
     *
     * @param string $method HTTP method.
     * @param string $path Path relative to BASE_URI, without a leading slash.
     * @param array $options Guzzle options.
     * @param bool $forceprobe Whether an administrator connection test may probe an open circuit.
     * @return ResponseInterface
     */
    protected function request(
        string $method,
        string $path,
        array $options = [],
        bool $forceprobe = false
    ): ResponseInterface {
        return $this->send($method, $this->build_api_url($path), $options, $forceprobe);
    }

    /**
     * Send an authenticated request to a validated absolute URL.
     *
     * @param string $method HTTP method.
     * @param string $url Absolute URL previously validated as VirusTotal.
     * @param array $options Guzzle options.
     * @return ResponseInterface
     */
    protected function request_absolute(string $method, string $url, array $options = []): ResponseInterface {
        $this->assert_virustotal_upload_url($url);
        return $this->send($method, $url, $options);
    }

    /**
     * Perform the HTTP round-trip with the API key in the request header only.
     *
     * @param string $method HTTP method.
     * @param string $url Absolute URL.
     * @param array $options Guzzle options.
     * @param bool $forceprobe Whether an administrator connection test may probe an open circuit.
     * @return ResponseInterface
     */
    protected function send(
        string $method,
        string $url,
        array $options,
        bool $forceprobe = false
    ): ResponseInterface {
        $key = $this->credentials->get_api_key();
        $headers = $options['headers'] ?? [];
        $headers['x-apikey'] = $key;
        $headers['Accept'] = $headers['Accept'] ?? 'application/json';
        $options['headers'] = $headers;
        $options['http_errors'] = false;
        unset($options['debug']);

        $probelock = $this->health->before_request($forceprobe);
        try {
            try {
                $response = $this->http->request($method, $url, $options);
            } catch (NetworkExceptionInterface | GuzzleException $e) {
                $this->health->record_failure();
                throw new provider_exception(
                    'error_network',
                    provider_exception::redact($e->getMessage(), $key)
                );
            }
            $this->observe_availability($response);
            return $response;
        } finally {
            if ($probelock) {
                $probelock->release();
            }
        }
    }

    /**
     * Update the availability circuit from an HTTP status.
     *
     * 2xx, 404, and 401/403 mean VirusTotal answered. 429 and 5xx are
     * availability failures. Other client errors do not open the circuit.
     *
     * @param ResponseInterface $response HTTP response.
     */
    protected function observe_availability(ResponseInterface $response): void {
        $status = $response->getStatusCode();
        if (
            ($status >= 200 && $status < 300)
            || $status === 404
            || $status === 401
            || $status === 403
        ) {
            $this->health->record_success();
            return;
        }
        if ($status === 429 || $status >= 500) {
            $this->health->record_failure($this->parse_retry_after($response));
        }
    }

    /**
     * Build a VirusTotal API v3 URL from an internal relative path.
     *
     * @param string $path Relative path.
     * @return string
     */
    protected function build_api_url(string $path): string {
        $path = ltrim($path, '/');
        if ($path === '' || str_contains($path, '://') || str_starts_with($path, '//')) {
            throw new provider_exception('error_invalidrequest');
        }
        if (str_contains($path, '..')) {
            throw new provider_exception('error_invalidrequest');
        }
        return self::BASE_URI . '/' . $path;
    }

    /**
     * Allow only VirusTotal hosts for large-file upload URLs (SSRF control).
     *
     * @param string $url Candidate upload URL.
     */
    protected function assert_virustotal_upload_url(string $url): void {
        $parts = parse_url($url);
        if ($parts === false || !empty($parts['user']) || !empty($parts['pass'])) {
            throw new provider_exception('error_malformed');
        }
        $scheme = strtolower($parts['scheme'] ?? '');
        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new provider_exception('error_malformed');
        }
        $host = strtolower($parts['host'] ?? '');
        $allowed = $host === 'virustotal.com' || str_ends_with($host, '.virustotal.com');
        if (!$allowed) {
            throw new provider_exception('error_malformed');
        }
        if (isset($parts['port']) && !in_array((int) $parts['port'], [80, 443], true)) {
            throw new provider_exception('error_malformed');
        }
    }

    /**
     * Reject hashes that are not lowercase hex SHA-256.
     *
     * @param string $sha256 Candidate hash.
     */
    protected function assert_sha256(string $sha256): void {
        if (!preg_match('/^[a-f0-9]{64}$/', $sha256)) {
            throw new provider_exception('error_invalidrequest');
        }
    }

    /**
     * Reject analysis identifiers that are empty or contain path characters.
     *
     * @param string $analysisid Candidate analysis id.
     */
    protected function assert_analysis_id(string $analysisid): void {
        $length = strlen($analysisid);
        if (
            $length < 8 || $length > 255 || str_contains($analysisid, '/')
                || str_contains($analysisid, '\\') || str_contains($analysisid, '..')
        ) {
            throw new provider_exception('error_invalidrequest');
        }
        if (!preg_match('/^[A-Za-z0-9=_-]+$/', $analysisid)) {
            throw new provider_exception('error_invalidrequest');
        }
    }

    /**
     * Decode the body where possible, then require HTTP success.
     *
     * A body that fails to parse is only a malformed-response error on a 2xx
     * status. On an error status the status classification wins, so transient
     * responses such as 429 and 5xx stay retryable even when the body is HTML
     * or empty.
     *
     * @param ResponseInterface $response HTTP response.
     * @param bool $notfoundiserror Whether 404 is a not-found error.
     * @return array Decoded body, empty when an error body could not be parsed.
     */
    protected function require_success_body(ResponseInterface $response, bool $notfoundiserror = true): array {
        $body = $response->getBody()->getContents();
        $decoded = [];
        if ($body !== '') {
            try {
                $decoded = $this->decode_json($body);
            } catch (provider_exception $e) {
                if ($response->getStatusCode() >= 200 && $response->getStatusCode() < 300) {
                    throw $e;
                }
                $decoded = [];
            }
        }
        $this->throw_for_status($response, $notfoundiserror, $decoded);
        return $decoded;
    }

    /**
     * Decode JSON, require HTTP success, and return the data object.
     *
     * @param ResponseInterface $response HTTP response.
     * @return array
     */
    protected function require_success_data(ResponseInterface $response): array {
        $decoded = $this->require_success_body($response);
        $data = $decoded['data'] ?? null;
        if (!is_array($data)) {
            throw new provider_exception('error_malformed');
        }
        return $data;
    }

    /**
     * Map HTTP status codes to provider exceptions.
     *
     * @param ResponseInterface $response HTTP response.
     * @param bool $notfoundiserror Whether 404 is an error (false for hash lookup).
     * @param array $decoded Optional decoded body.
     */
    protected function throw_for_status(
        ResponseInterface $response,
        bool $notfoundiserror,
        array $decoded = []
    ): void {
        $status = $response->getStatusCode();
        if ($status >= 200 && $status < 300) {
            return;
        }

        $retryafter = $this->parse_retry_after($response);
        $vtcode = '';
        if (isset($decoded['error']) && is_array($decoded['error'])) {
            $vtcode = (string) ($decoded['error']['code'] ?? '');
        }

        $errorcode = match (true) {
            $status === 401 => 'error_auth',
            $status === 403 => 'error_forbidden',
            $status === 404 && $notfoundiserror => 'error_notfound',
            $status === 413 => 'error_filetoolarge',
            $status === 429 => 'error_ratelimit',
            $status === 400, $status === 422 => 'error_invalidrequest',
            $status >= 500 => 'error_server',
            default => 'error_generic',
        };

        throw new provider_exception($errorcode, $vtcode, $status, $retryafter);
    }

    /**
     * Parse Retry-After as delta-seconds or HTTP-date, then cap it.
     *
     * Malformed, negative, zero, and past dates are ignored. An unbounded
     * future date is clamped to {@see retry_policy::DELAY_MAX}.
     *
     * @param ResponseInterface $response HTTP response.
     * @return int|null
     */
    protected function parse_retry_after(ResponseInterface $response): ?int {
        $header = trim($response->getHeaderLine('Retry-After'));
        if ($header === '') {
            return null;
        }
        if (ctype_digit($header)) {
            return retry_policy::cap_delay((int) $header);
        }
        if (preg_match('/^-?\d+$/', $header)) {
            return null;
        }
        $timestamp = strtotime($header);
        if ($timestamp === false) {
            return null;
        }
        return retry_policy::cap_delay($timestamp - time());
    }

    /**
     * Decode a JSON object or array from an untrusted HTTP body.
     *
     * @param string $body Response body.
     * @return array
     */
    protected function decode_json(string $body): array {
        if ($body === '') {
            throw new provider_exception('error_malformed');
        }
        try {
            $data = json_decode($body, true, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new provider_exception('error_malformed');
        }
        if (!is_array($data)) {
            throw new provider_exception('error_malformed');
        }
        return $data;
    }

    /**
     * Copy known engine-count keys only.
     *
     * @param mixed $stats Raw stats object.
     * @return array|null
     */
    protected function normalise_stats(mixed $stats): ?array {
        if (!is_array($stats)) {
            return null;
        }
        $keys = ['malicious', 'suspicious', 'undetected', 'harmless', 'timeout'];
        $out = [];
        foreach ($keys as $key) {
            if (array_key_exists($key, $stats) && is_numeric($stats[$key])) {
                $out[$key] = (int) $stats[$key];
            }
        }
        return $out === [] ? null : $out;
    }

    /**
     * Derive engine counts from last_analysis_results when stats are absent.
     *
     * @param mixed $results Per-engine result map.
     * @return array|null
     */
    protected function stats_from_analysis_results(mixed $results): ?array {
        if (!is_array($results) || $results === []) {
            return null;
        }
        $counts = [
            'malicious' => 0,
            'suspicious' => 0,
            'undetected' => 0,
            'harmless' => 0,
            'timeout' => 0,
        ];
        $any = false;
        foreach ($results as $engine) {
            if (!is_array($engine)) {
                continue;
            }
            $category = strtolower((string) ($engine['category'] ?? ''));
            if ($category === 'malicious') {
                $counts['malicious']++;
                $any = true;
            } else if ($category === 'suspicious') {
                $counts['suspicious']++;
                $any = true;
            } else if ($category === 'undetected' || $category === 'type-unsupported' || $category === 'failure') {
                $counts['undetected']++;
                $any = true;
            } else if ($category === 'harmless') {
                $counts['harmless']++;
                $any = true;
            } else if ($category === 'timeout' || $category === 'confirmed-timeout') {
                $counts['timeout']++;
                $any = true;
            }
        }
        return $any ? $counts : null;
    }

    /**
     * Return a string attribute when present and typed correctly.
     *
     * @param array $data Parent array.
     * @param string $key Key.
     * @return string|null
     */
    protected function optional_string(array $data, string $key): ?string {
        if (!array_key_exists($key, $data) || !is_string($data[$key])) {
            return null;
        }
        return $data[$key];
    }

    /**
     * Return an integer attribute when present and numeric.
     *
     * @param array $data Parent array.
     * @param string $key Key.
     * @return int|null
     */
    protected function optional_int(array $data, string $key): ?int {
        if (!array_key_exists($key, $data) || !is_numeric($data[$key])) {
            return null;
        }
        return (int) $data[$key];
    }

    /**
     * Return an array attribute when present and typed correctly.
     *
     * @param array $data Parent array.
     * @param string $key Key.
     * @return array|null
     */
    protected function optional_array(array $data, string $key): ?array {
        if (!array_key_exists($key, $data) || !is_array($data[$key])) {
            return null;
        }
        return $data[$key];
    }
}
