<?php

declare(strict_types=1);

// PHP conformance adapter, backed by the mpp-php SDK.
//
// Reads one AdapterRequest from stdin, writes one AdapterResponse to stdout.
// The harness represents a challenge `request` as a decoded object; the SDK holds it in wire
// form, so the two are translated at this boundary.

require __DIR__ . '/vendor/autoload.php';

use Mpp\Base64Url;
use Mpp\Challenge;
use Mpp\Credential;
use Mpp\Exception\ParseException;
use Mpp\Jcs;
use Mpp\Receipt;

const MINIMUM_SECRET_BYTES = 32;

/** @return array{ok: true, value: mixed} */
function ok(mixed $value): array
{
    return ['ok' => true, 'value' => $value];
}

/** @return array{ok: false, error: array{type: string, message: string}} */
function err(string $message, string $type): array
{
    return ['ok' => false, 'error' => ['type' => $type, 'message' => $message]];
}

/**
 * @param array<string, mixed> $input
 */
function challengeFromObject(array $input): Challenge
{
    $request = $input['request'] ?? [];

    return new Challenge(
        id: (string) ($input['id'] ?? ''),
        realm: (string) ($input['realm'] ?? ''),
        method: (string) ($input['method'] ?? ''),
        intent: (string) ($input['intent'] ?? ''),
        request: is_string($request) ? $request : Base64Url::encodeJson($request),
        digest: isset($input['digest']) ? (string) $input['digest'] : null,
        expires: isset($input['expires']) ? (string) $input['expires'] : null,
        description: isset($input['description']) ? (string) $input['description'] : null,
        header: isset($input['header']) ? (string) $input['header'] : null,
        opaque: isset($input['opaque']) ? (string) $input['opaque'] : null,
    );
}

/** @return array<string, mixed> */
function challengeToObject(Challenge $challenge): array
{
    $out = [
        'id' => $challenge->id,
        'realm' => $challenge->realm,
        'method' => $challenge->method,
        'intent' => $challenge->intent,
        // Cast so an empty object serializes as {} and not [].
        'request' => (object) $challenge->decodeRequest(),
    ];

    foreach (['expires', 'description', 'digest', 'header', 'opaque'] as $optional) {
        if ($challenge->{$optional} !== null) {
            $out[$optional] = $challenge->{$optional};
        }
    }

    return $out;
}

/**
 * @param array<string, mixed> $input
 */
function challengeId(array $input): string
{
    $secret = (string) ($input['secretKey'] ?? '');
    if (strlen($secret) < MINIMUM_SECRET_BYTES) {
        throw new InvalidArgumentException('secretKey must be at least ' . MINIMUM_SECRET_BYTES . ' bytes');
    }

    $header = isset($input['header']) ? (string) $input['header'] : null;

    $slots = [
        (string) ($input['realm'] ?? ''),
        (string) ($input['method'] ?? ''),
        (string) ($input['intent'] ?? ''),
        Base64Url::encode(Jcs::encode($input['request'] ?? new stdClass())),
        isset($input['expires']) ? (string) $input['expires'] : '',
        isset($input['digest']) ? (string) $input['digest'] : '',
    ];

    // The default credential field is not part of the binding input.
    if ($header !== null && strcasecmp($header, 'Authorization') !== 0) {
        $slots[] = $header;
    }

    $slots[] = isset($input['opaque']) ? (string) $input['opaque'] : '';

    return Base64Url::encode(hash_hmac('sha256', implode('|', $slots), $secret, true));
}

/**
 * @return array{ok: bool, value?: mixed, error?: array{type: string, message: string}}
 */
function dispatch(string $op, mixed $input): array
{
    /** @var array<string, mixed> $in */
    $in = is_array($input) ? $input : [];

    switch ($op) {
        case 'base64url.encode':
            return ok(['text' => Base64Url::encode((string) ($in['text'] ?? ''))]);

        case 'base64url.decode':
            // The generic operation tolerates padding; protocol fields never carry it.
            return ok(['text' => Base64Url::decode(rtrim((string) ($in['text'] ?? ''), '='))]);

        case 'challenge.parse':
            return ok(challengeToObject(Challenge::fromHeader((string) ($in['header'] ?? ''))));

        case 'challenge.format':
            return ok(['header' => challengeFromObject($in)->toHeader()]);

        case 'challenge.id':
            return ok(['id' => challengeId($in)]);

        case 'credential.parse':
            $credential = Credential::fromHeader((string) ($in['header'] ?? ''));
            $value = ['challenge' => (object) challengeToObject($credential->challenge), 'payload' => (object) $credential->payload];
            if ($credential->source !== null) {
                $value['source'] = $credential->source;
            }

            return ok($value);

        case 'credential.format':
            /** @var array<string, mixed> $challenge */
            $challenge = is_array($in['challenge'] ?? null) ? $in['challenge'] : [];
            /** @var array<string, mixed> $payload */
            $payload = is_array($in['payload'] ?? null) ? $in['payload'] : [];
            $source = isset($in['source']) ? (string) $in['source'] : null;

            return ok(['header' => (new Credential(challengeFromObject($challenge), $payload, $source))->toHeader()]);

        case 'receipt.parse':
            $receipt = Receipt::fromHeader((string) ($in['header'] ?? ''));

            return ok([
                'status' => Receipt::STATUS_SUCCESS,
                'method' => $receipt->method,
                'timestamp' => $receipt->timestamp,
                'reference' => $receipt->reference,
                ...$receipt->extra,
            ]);

        case 'receipt.format':
            $extra = $in;
            unset($extra['status'], $extra['method'], $extra['timestamp'], $extra['reference']);

            $receipt = new Receipt(
                (string) ($in['method'] ?? ''),
                (string) ($in['reference'] ?? ''),
                (string) ($in['timestamp'] ?? ''),
                $extra,
            );

            return ok(['header' => $receipt->toHeader()]);

        default:
            return err("unsupported operation: {$op}", 'unsupported_operation');
    }
}

function errorTypeFor(string $op, Throwable $e): string
{
    if ($e instanceof InvalidArgumentException) {
        return 'generation_error';
    }
    if (!$e instanceof ParseException) {
        return 'unknown_error';
    }

    return match (true) {
        str_starts_with($op, 'base64url.') => 'encoding_error',
        str_ends_with($op, '.format') => 'format_error',
        $op === 'challenge.id' => 'generation_error',
        default => 'parse_error',
    };
}

$raw = stream_get_contents(STDIN);
$request = json_decode($raw === false ? '' : $raw, true);

if (!is_array($request) || !isset($request['op']) || !is_string($request['op'])) {
    echo json_encode(err('request must be a JSON object with an op', 'unknown_error')), PHP_EOL;
    exit(0);
}

$op = $request['op'];

try {
    $response = dispatch($op, $request['input'] ?? null);
} catch (Throwable $e) {
    $response = err($e->getMessage(), errorTypeFor($op, $e));
}

echo json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), PHP_EOL;
