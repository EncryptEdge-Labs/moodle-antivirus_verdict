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
 * Tests for the VirusTotal API v3 client.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict;

use core\http_client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use antivirus_verdict\local\provider_health;
use antivirus_verdict\local\retry_policy;
use antivirus_verdict\provider\file_payload;
use antivirus_verdict\provider\provider_exception;
use antivirus_verdict\provider\virustotal\client;
use antivirus_verdict\tests\test_credentials;
use antivirus_verdict\tests\testable_provider_health;
use antivirus_verdict\tests\testable_vt_client;


/**
 * Unit tests for the isolated VirusTotal API v3 client.
 *
 * @covers \antivirus_verdict\provider\virustotal\client
 */
final class client_test extends \advanced_testcase {
    /** Placeholder credential used only in unit tests. */
    private const FAKE_KEY = 'phpunit-fake-key';

    /** Valid SHA-256 used in request-path tests. */
    private const SHA256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /**
     * Hash lookup uses the v3 files endpoint and sends x-apikey server-side.
     */
    public function test_hash_lookup_endpoint_and_auth_header(): void {
        $body = json_encode([
            'data' => [
                'id' => self::SHA256,
                'type' => 'file',
                'attributes' => [
                    'sha256' => self::SHA256,
                    'last_analysis_stats' => [
                        'malicious' => 1,
                        'suspicious' => 2,
                        'undetected' => 50,
                        'harmless' => 3,
                        'timeout' => 0,
                    ],
                    'last_analysis_date' => 1700000000,
                    'meaningful_name' => 'sample.bin',
                ],
            ],
        ]);
        [$vtclient, $mock] = $this->make_client([new Response(200, [], $body)]);
        $result = $vtclient->lookup_file_hash(self::SHA256);
        $request = $mock->getLastRequest();

        $this->assertSame('/api/v3/files/' . self::SHA256, $request->getUri()->getPath());
        $this->assertSame('www.virustotal.com', $request->getUri()->getHost());
        $this->assertTrue($request->hasHeader('x-apikey'));
        $this->assertSame(self::FAKE_KEY, $request->getHeaderLine('x-apikey'));
        $this->assertTrue($result->found);
        $this->assertSame(self::SHA256, $result->sha256);
        $this->assertSame(1, $result->lastanalysisstats['malicious']);
        $this->assertStringNotContainsString(self::FAKE_KEY, json_encode($result));
    }

    /**
     * Engine categories are counted when last_analysis_stats is omitted.
     */
    public function test_hash_lookup_derives_stats_from_engine_results(): void {
        $body = json_encode([
            'data' => [
                'id' => self::SHA256,
                'type' => 'file',
                'attributes' => [
                    'sha256' => self::SHA256,
                    'last_analysis_results' => [
                        'EngineA' => ['category' => 'malicious'],
                        'EngineB' => ['category' => 'malicious'],
                        'EngineC' => ['category' => 'undetected'],
                    ],
                ],
            ],
        ]);
        [$vtclient] = $this->make_client([new Response(200, [], $body)]);
        $result = $vtclient->lookup_file_hash(self::SHA256);
        $this->assertTrue($result->found);
        $this->assertSame(2, $result->lastanalysisstats['malicious']);
        $this->assertSame(1, $result->lastanalysisstats['undetected']);
        $this->assertArrayNotHasKey('last_analysis_stats', json_decode($body, true)['data']['attributes']);
        $this->assertSame(
            scan_status::MALICIOUS,
            (new \antivirus_verdict\local\result_normaliser())->status_from_stats($result->lastanalysisstats)
        );
        $this->assertStringNotContainsString(self::FAKE_KEY, json_encode($result));
    }
    public function test_unknown_hash_is_not_found(): void {
        [$vtclient] = $this->make_client([new Response(404, [], '{"error":{"code":"NotFoundError"}}')]);
        $result = $vtclient->lookup_file_hash(self::SHA256);
        $this->assertFalse($result->found);
        $this->assertSame(self::SHA256, $result->sha256);
        $this->assertStringNotContainsString(self::FAKE_KEY, json_encode($result));
    }

    /**
     * Upload returns a normalised analysis identifier.
     */
    public function test_upload_is_normalised(): void {
        $body = json_encode(['data' => ['type' => 'analysis', 'id' => 'analysis-id-001']]);
        [$vtclient, $mock] = $this->make_client([new Response(200, [], $body)]);
        $result = $vtclient->upload_file(new file_payload('hello', 'hello.txt'));
        $request = $mock->getLastRequest();

        $this->assertSame('/api/v3/files', $request->getUri()->getPath());
        $this->assertSame('POST', $request->getMethod());
        $this->assertTrue($request->hasHeader('x-apikey'));
        $this->assertSame('analysis-id-001', $result->analysisid);
        $this->assertStringNotContainsString(self::FAKE_KEY, json_encode($result));
    }

    /**
     * Analysis retrieval is normalised without product verdicts.
     */
    public function test_analysis_retrieval_is_normalised(): void {
        $body = json_encode([
            'data' => [
                'id' => 'analysis-id-001',
                'type' => 'analysis',
                'attributes' => [
                    'status' => 'completed',
                    'stats' => ['malicious' => 4, 'suspicious' => 0, 'undetected' => 60],
                ],
            ],
        ]);
        [$vtclient, $mock] = $this->make_client([new Response(200, [], $body)]);
        $result = $vtclient->get_analysis('analysis-id-001');
        $request = $mock->getLastRequest();

        $this->assertSame('/api/v3/analyses/analysis-id-001', $request->getUri()->getPath());
        $this->assertSame('completed', $result->status);
        $this->assertSame(4, $result->stats['malicious']);
        $this->assertStringNotContainsString(self::FAKE_KEY, json_encode($result));
    }

    /**
     * Invalid JSON on success status is a malformed-response error.
     */
    public function test_invalid_json_is_malformed(): void {
        [$vtclient] = $this->make_client([new Response(200, [], '{not-json')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_malformed', $e->errorcode);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * HTTP 401 is an authentication error.
     */
    public function test_http_401_is_auth_error(): void {
        [$vtclient] = $this->make_client([new Response(401, [], '{"error":{"code":"AuthenticationRequiredError"}}')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_auth', $e->errorcode);
            $this->assertSame(401, $e->httpstatus);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * HTTP 403 is an authorisation / plan error.
     */
    public function test_http_403_is_forbidden(): void {
        [$vtclient] = $this->make_client([new Response(403, [], '{"error":{"code":"ForbiddenError"}}')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_forbidden', $e->errorcode);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * HTTP 429 is a rate-limit error and exposes Retry-After when numeric.
     */
    public function test_http_429_is_rate_limit(): void {
        [$vtclient] = $this->make_client([new Response(429, ['Retry-After' => '12'], '{}')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_ratelimit', $e->errorcode);
            $this->assertSame(12, $e->retryafter);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * HTTP 5xx is a provider server error.
     */
    public function test_http_500_is_server_error(): void {
        [$vtclient] = $this->make_client([new Response(500, [], 'oops')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_server', $e->errorcode);
            $this->assertSame(500, $e->httpstatus);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * HTTP 502 is a provider server error.
     */
    public function test_http_502_is_server_error(): void {
        [$vtclient] = $this->make_client([new Response(502, [], 'bad gateway')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_server', $e->errorcode);
            $this->assertSame(502, $e->httpstatus);
        }
    }

    /**
     * HTTP 503 is a provider server error.
     */
    public function test_http_503_is_server_error(): void {
        [$vtclient] = $this->make_client([new Response(503, [], 'unavailable')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_server', $e->errorcode);
            $this->assertSame(503, $e->httpstatus);
        }
    }

    /**
     * HTTP 504 is a provider server error.
     */
    public function test_http_504_is_server_error(): void {
        [$vtclient] = $this->make_client([new Response(504, [], 'gateway timeout')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_server', $e->errorcode);
            $this->assertSame(504, $e->httpstatus);
        }
    }

    /**
     * Network failures are normalised.
     */
    public function test_network_failure_is_normalised(): void {
        $request = new Request('GET', client::BASE_URI . '/files/' . self::SHA256);
        [$vtclient] = $this->make_client([
            new ConnectException('Connection refused phpunit-fake-key', $request),
        ]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_network', $e->errorcode);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * Request timeouts are network failures, not verdicts.
     */
    public function test_timeout_is_network_error(): void {
        $request = new Request('GET', client::BASE_URI . '/files/' . self::SHA256);
        [$vtclient] = $this->make_client([
            new ConnectException('cURL error 28: Operation timed out for phpunit-fake-key', $request),
        ]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_network', $e->errorcode);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * Missing data object is malformed, not a fatal PHP error.
     */
    public function test_unexpected_structure_is_malformed(): void {
        [$vtclient] = $this->make_client([new Response(200, [], '{"hello":"world"}')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_malformed', $e->errorcode);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * A URL cannot be supplied as a hash (SSRF / invalid request).
     */
    public function test_hash_rejects_arbitrary_url(): void {
        [$vtclient, $mock] = $this->make_client([]);
        try {
            $vtclient->lookup_file_hash('https://evil.example/steal');
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_invalidrequest', $e->errorcode);
            $this->assertNull($mock->getLastRequest());
        }
    }

    /**
     * Relative API paths cannot be turned into absolute third-party URLs.
     */
    public function test_build_url_rejects_absolute_urls(): void {
        [$vtclient] = $this->make_client([]);
        try {
            $vtclient->public_build_api_url('https://evil.example/x');
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_invalidrequest', $e->errorcode);
        }
    }

    /**
     * Large-file upload URLs must be on virustotal.com.
     */
    public function test_upload_url_rejects_foreign_hosts(): void {
        [$vtclient] = $this->make_client([]);
        try {
            $vtclient->public_assert_upload_url('https://evil.example/upload');
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_malformed', $e->errorcode);
        }
    }

    /**
     * Official VirusTotal upload hosts are accepted.
     */
    public function test_upload_url_allows_virustotal_host(): void {
        [$vtclient] = $this->make_client([]);
        $vtclient->public_assert_upload_url('https://www.virustotal.com/_ah/upload/abc');
        $this->assertTrue(true);
    }

    /**
     * Files over the documented large-upload limit fail without an HTTP call.
     */
    public function test_file_too_large_for_provider(): void {
        [$vtclient, $mock] = $this->make_client([]);
        $vtclient->largemax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'big.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_filetoolarge', $e->errorcode);
            $this->assertNull($mock->getLastRequest());
        }
    }

    /**
     * Files above the direct-upload limit use GET /files/upload_url then POST.
     */
    public function test_large_upload_uses_validated_upload_url(): void {
        $uploadurl = 'https://www.virustotal.com/_ah/upload/token';
        $responses = [
            new Response(200, [], json_encode(['data' => $uploadurl])),
            new Response(200, [], json_encode(['data' => ['id' => 'analysis-large-1']])),
        ];
        [$vtclient, $mock] = $this->make_client($responses);
        $vtclient->directmax = 4;
        $result = $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
        $this->assertSame('analysis-large-1', $result->analysisid);
        $last = $mock->getLastRequest();
        $this->assertSame('POST', $last->getMethod());
        $this->assertSame('/_ah/upload/token', $last->getUri()->getPath());
        $this->assertSame('www.virustotal.com', $last->getUri()->getHost());
        $this->assertTrue($last->hasHeader('x-apikey'));
    }

    /**
     * A VirusTotal upload_url pointing off-site is rejected (SSRF control).
     */
    public function test_large_upload_rejects_foreign_upload_url(): void {
        $responses = [
            new Response(200, [], json_encode(['data' => 'https://evil.example/upload'])),
        ];
        [$vtclient, $mock] = $this->make_client($responses);
        $vtclient->directmax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_malformed', $e->errorcode);
            $this->assertSame('GET', $mock->getLastRequest()->getMethod());
            $this->assertSame('/api/v3/files/upload_url', $mock->getLastRequest()->getUri()->getPath());
        }
    }

    /**
     * A rate-limited upload_url stays retryable and keeps Retry-After.
     */
    public function test_large_upload_url_rate_limit_is_retryable(): void {
        [$vtclient, $mock] = $this->make_client([new Response(429, ['Retry-After' => '30'], 'Too Many Requests')]);
        $vtclient->directmax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_ratelimit', $e->errorcode);
            $this->assertSame(429, $e->httpstatus);
            $this->assertSame(30, $e->retryafter);
            $this->assertSame('/api/v3/files/upload_url', $mock->getLastRequest()->getUri()->getPath());
            $this->assert_secret_absent($e);
        }
    }

    /**
     * A 5xx upload_url response is a server error, not a malformed response.
     */
    public function test_large_upload_url_server_error_is_not_malformed(): void {
        [$vtclient] = $this->make_client([new Response(503, [], '<html>Service Unavailable</html>')]);
        $vtclient->directmax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_server', $e->errorcode);
            $this->assertSame(503, $e->httpstatus);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * An interrupted large-file POST is classified as upload-interrupted, not retried here.
     */
    public function test_large_upload_post_interruption_is_not_indeterminate_retry(): void {
        $uploadurl = 'https://www.virustotal.com/_ah/upload/token';
        $request = new Request('POST', $uploadurl);
        [$vtclient, $mock] = $this->make_client([
            new Response(200, [], json_encode(['data' => $uploadurl])),
            new ConnectException('cURL error 28: Operation timed out', $request),
        ]);
        $vtclient->directmax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_uploadinterrupted', $e->errorcode);
            $this->assertSame('POST', $mock->getLastRequest()->getMethod());
            $this->assertSame('/_ah/upload/token', $mock->getLastRequest()->getUri()->getPath());
            $this->assert_secret_absent($e);
        }
        $this->assertSame(0, $mock->count());
    }

    /**
     * A large-file POST 5xx is upload-interrupted; the URL GET is not reclassified.
     */
    public function test_large_upload_post_server_error_is_interrupted(): void {
        $uploadurl = 'https://www.virustotal.com/_ah/upload/token';
        [$vtclient] = $this->make_client([
            new Response(200, [], json_encode(['data' => $uploadurl])),
            new Response(502, [], 'bad gateway'),
        ]);
        $vtclient->directmax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_uploadinterrupted', $e->errorcode);
            $this->assertSame(502, $e->httpstatus);
        }
    }

    /**
     * Authentication failure on a large POST is permanent, not an interrupted transfer.
     */
    public function test_large_upload_post_auth_is_permanent(): void {
        $uploadurl = 'https://www.virustotal.com/_ah/upload/token';
        [$vtclient] = $this->make_client([
            new Response(200, [], json_encode(['data' => $uploadurl])),
            new Response(401, [], '{"error":{"code":"AuthenticationRequiredError"}}'),
        ]);
        $vtclient->directmax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_auth', $e->errorcode);
            $this->assertSame(401, $e->httpstatus);
        }
    }

    /**
     * Unparsable JSON on a successful upload_url response is malformed.
     */
    public function test_large_upload_url_malformed_success_body(): void {
        [$vtclient] = $this->make_client([new Response(200, [], '{not-json')]);
        $vtclient->directmax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_malformed', $e->errorcode);
            $this->assert_secret_absent($e);
        }
    }

    /**
     * A successful upload_url response without a URL is malformed.
     */
    public function test_large_upload_url_missing_url_is_malformed(): void {
        [$vtclient, $mock] = $this->make_client([new Response(200, [], json_encode(['data' => '']))]);
        $vtclient->directmax = 4;
        try {
            $vtclient->upload_file(new file_payload('12345', 'mid.bin'));
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_malformed', $e->errorcode);
            $this->assertSame('/api/v3/files/upload_url', $mock->getLastRequest()->getUri()->getPath());
        }
    }

    /**
     * Connection test treats 200 and 404 as credential success.
     */
    public function test_connection_success_on_404(): void {
        [$vtclient] = $this->make_client([new Response(404, [], '{"error":{"code":"NotFoundError"}}')]);
        $result = $vtclient->test_connection();
        $this->assertTrue($result->success);
        $this->assertSame('connection_success', $result->code);
    }

    /**
     * Connection test maps 401 to authentication failure without exposing the key.
     */
    public function test_connection_auth_failure(): void {
        [$vtclient] = $this->make_client([new Response(401, [], '{}')]);
        $result = $vtclient->test_connection();
        $this->assertFalse($result->success);
        $this->assertSame('error_auth', $result->code);
        $this->assertStringNotContainsString(self::FAKE_KEY, json_encode($result));
    }

    /**
     * Connection test treats rate limiting as a failed check, not as success.
     */
    public function test_connection_rate_limit_is_not_success(): void {
        [$vtclient] = $this->make_client([new Response(429, ['Retry-After' => '8'], '{}')]);
        $result = $vtclient->test_connection();
        $this->assertFalse($result->success);
        $this->assertSame('error_ratelimit', $result->code);
    }

    /**
     * An administrator connection test may probe during an open cooldown.
     */
    public function test_connection_test_probes_open_circuit(): void {
        $health = $this->make_health();
        [$vtclient, $mock, $health] = $this->make_client([
            new Response(404, [], '{"error":{"code":"NotFoundError"}}'),
        ], $health);
        $health->seed(provider_health::STATE_OPEN, 5, $health->clock + 60);
        $result = $vtclient->test_connection();
        $this->assertTrue($result->success);
        $this->assertSame('connection_success', $result->code);
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertNotNull($mock->getLastRequest());
    }

    /**
     * Retry-After delta-seconds is parsed and used.
     */
    public function test_retry_after_delta_seconds(): void {
        [$vtclient] = $this->make_client([new Response(429, ['Retry-After' => '12'], '{}')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame(12, $e->retryafter);
        }
    }

    /**
     * Retry-After HTTP-date is converted to a capped delay.
     */
    public function test_retry_after_http_date(): void {
        [$vtclient] = $this->make_client([]);
        $header = gmdate('D, d M Y H:i:s', time() + 90) . ' GMT';
        $parsed = $vtclient->public_parse_retry_after(new Response(429, ['Retry-After' => $header], '{}'));
        $this->assertNotNull($parsed);
        $this->assertGreaterThanOrEqual(85, $parsed);
        $this->assertLessThanOrEqual(90, $parsed);
    }

    /**
     * Malformed Retry-After is ignored rather than treated as an unbounded sleep.
     */
    public function test_retry_after_malformed_is_ignored(): void {
        [$vtclient] = $this->make_client([new Response(429, ['Retry-After' => 'not-a-delay'], '{}')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_ratelimit', $e->errorcode);
            $this->assertNull($e->retryafter);
        }
    }

    /**
     * Excessive Retry-After is capped at the retry-policy maximum.
     */
    public function test_retry_after_excessive_is_capped(): void {
        [$vtclient] = $this->make_client([new Response(429, ['Retry-After' => '99999'], '{}')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame(retry_policy::DELAY_MAX, $e->retryafter);
        }
    }

    /**
     * Missing Retry-After leaves the delay unset so the policy fallback is used.
     */
    public function test_retry_after_missing_is_null(): void {
        [$vtclient] = $this->make_client([new Response(429, [], '{}')]);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertNull($e->retryafter);
        }
        [$vtclient] = $this->make_client([]);
        $this->assertNull($vtclient->public_parse_retry_after(new Response(429, ['Retry-After' => '-5'], '{}')));
        $this->assertNull($vtclient->public_parse_retry_after(new Response(429, ['Retry-After' => '0'], '{}')));
    }

    /**
     * Closed circuit lets a normal hash lookup proceed.
     */
    public function test_closed_circuit_performs_request(): void {
        $body = json_encode([
            'data' => [
                'id' => self::SHA256,
                'type' => 'file',
                'attributes' => [
                    'sha256' => self::SHA256,
                    'last_analysis_stats' => [
                        'malicious' => 0,
                        'suspicious' => 0,
                        'undetected' => 50,
                        'harmless' => 3,
                        'timeout' => 0,
                    ],
                ],
            ],
        ]);
        $health = $this->make_health();
        [$vtclient, $mock, $health] = $this->make_client([new Response(200, [], $body)], $health);
        $result = $vtclient->lookup_file_hash(self::SHA256);
        $this->assertTrue($result->found);
        $this->assertSame(0, $result->lastanalysisstats['malicious']);
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertSame(0, $health->failure_count());
        $this->assertNotNull($mock->getLastRequest());
    }

    /**
     * Repeated availability failures open the circuit and skip later HTTP.
     */
    public function test_failure_threshold_opens_and_skips_http(): void {
        $health = $this->make_health();
        $health->threshold = 2;
        $responses = [
            new Response(503, [], 'unavailable'),
            new Response(503, [], 'unavailable'),
        ];
        [$vtclient, $mock, $health] = $this->make_client($responses, $health);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_server', $e->errorcode);
        }
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_server', $e->errorcode);
        }
        $this->assertSame(provider_health::STATE_OPEN, $health->state());
        $this->assertSame(0, $mock->count());
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_providerunavailable', $e->errorcode);
        }
        $this->assertSame(0, $mock->count());
    }

    /**
     * After cooldown a successful probe closes the circuit.
     */
    public function test_halfopen_probe_success_closes_circuit(): void {
        $body = json_encode([
            'data' => [
                'id' => self::SHA256,
                'type' => 'file',
                'attributes' => [
                    'sha256' => self::SHA256,
                    'last_analysis_stats' => [
                        'malicious' => 1,
                        'suspicious' => 0,
                        'undetected' => 10,
                        'harmless' => 0,
                        'timeout' => 0,
                    ],
                ],
            ],
        ]);
        $health = $this->make_health();
        [$vtclient, $mock, $health] = $this->make_client([new Response(200, [], $body)], $health);
        $health->seed(provider_health::STATE_OPEN, 5, $health->clock - 1);
        $result = $vtclient->lookup_file_hash(self::SHA256);
        $this->assertTrue($result->found);
        $this->assertSame(1, $result->lastanalysisstats['malicious']);
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertSame(0, $health->failure_count());
        $this->assertNotNull($mock->getLastRequest());
    }

    /**
     * A failed half-open probe re-opens without becoming a verdict.
     */
    public function test_halfopen_probe_failure_reopens_circuit(): void {
        $health = $this->make_health();
        [$vtclient, $mock, $health] = $this->make_client([new Response(503, [], 'unavailable')], $health);
        $health->seed(provider_health::STATE_OPEN, 5, $health->clock - 1);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_server', $e->errorcode);
        }
        $this->assertSame(provider_health::STATE_OPEN, $health->state());
        $this->assertSame(0, $mock->count());
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_providerunavailable', $e->errorcode);
        }
    }

    /**
     * Authentication failures do not open the availability circuit.
     */
    public function test_auth_failure_does_not_open_circuit(): void {
        $health = $this->make_health();
        $health->threshold = 2;
        [$vtclient, $mock, $health] = $this->make_client([
            new Response(401, [], '{}'),
            new Response(403, [], '{}'),
            new Response(401, [], '{}'),
        ], $health);
        foreach (['error_auth', 'error_forbidden', 'error_auth'] as $expected) {
            try {
                $vtclient->lookup_file_hash(self::SHA256);
                $this->fail('Expected provider_exception');
            } catch (provider_exception $e) {
                $this->assertSame($expected, $e->errorcode);
            }
        }
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertSame(0, $health->failure_count());
        $this->assertSame(0, $mock->count());
    }

    /**
     * A malformed 200 response means the provider answered; the circuit stays closed.
     */
    public function test_malformed_success_does_not_open_circuit(): void {
        $health = $this->make_health();
        [$vtclient, , $health] = $this->make_client([new Response(200, [], '{"hello":"world"}')], $health);
        try {
            $vtclient->lookup_file_hash(self::SHA256);
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_malformed', $e->errorcode);
        }
        $this->assertSame(provider_health::STATE_CLOSED, $health->state());
        $this->assertSame(0, $health->failure_count());
    }

    /**
     * Invalid SHA-256 is rejected before HTTP.
     */
    public function test_invalid_sha256_rejected(): void {
        [$vtclient, $mock] = $this->make_client([]);
        try {
            $vtclient->lookup_file_hash('not-a-hash');
            $this->fail('Expected provider_exception');
        } catch (provider_exception $e) {
            $this->assertSame('error_invalidrequest', $e->errorcode);
            $this->assertNull($mock->getLastRequest());
        }
    }

    /**
     * Create a client backed by a Guzzle mock handler.
     *
     * @param array $responses Mocked responses or exceptions.
     * @param testable_provider_health|null $health Optional circuit instance.
     * @return array{0: testable_vt_client, 1: MockHandler, 2: testable_provider_health}
     */
    private function make_client(array $responses, ?testable_provider_health $health = null): array {
        $this->resetAfterTest();
        if ($health === null) {
            $health = $this->make_health();
        }
        $mock = new MockHandler($responses);
        $http = new http_client([
            'mock' => $mock,
            'http_errors' => false,
            'timeout' => 5,
            'connect_timeout' => 5,
            'ignoresecurity' => true,
        ]);
        $vtclient = new testable_vt_client(new test_credentials(self::FAKE_KEY), $http, $health);
        return [$vtclient, $mock, $health];
    }

    /**
     * Isolated circuit with a purged cache.
     *
     * @return testable_provider_health
     */
    private function make_health(): testable_provider_health {
        \cache::make('antivirus_verdict', provider_health::CACHE_AREA)->purge();
        return new testable_provider_health();
    }

    /**
     * Assert that a fake API key is not present in exception text.
     *
     * @param provider_exception $exception Exception to inspect.
     */
    private function assert_secret_absent(provider_exception $exception): void {
        $this->assertStringNotContainsString(self::FAKE_KEY, $exception->getMessage());
        $this->assertStringNotContainsString(self::FAKE_KEY, (string) $exception->debuginfo);
    }
}
