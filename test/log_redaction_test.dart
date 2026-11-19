import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:logging/logging.dart';
import 'package:signalr_netcore/errors.dart';
import 'package:signalr_netcore/http_connection.dart';
import 'package:signalr_netcore/http_connection_options.dart';
import 'package:signalr_netcore/ihub_protocol.dart';
import 'package:signalr_netcore/itransport.dart';
import 'package:signalr_netcore/log_redaction.dart';
import 'package:signalr_netcore/long_polling_transport.dart';
import 'package:signalr_netcore/server_sent_events_transport.dart';
import 'package:signalr_netcore/signalr_http_client.dart';
import 'package:signalr_netcore/web_socket_transport.dart';
import 'package:signalr_netcore/web_supporting_http_client.dart';

const String token = "SECRET-TOKEN-123";
const String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const String basicCredentials = "dXNlcjpwYXNzd29yZA==";

/// Collects every record of a logger at level ALL.
class LogCapture {
  final Logger logger = Logger.detached("capture");
  final List<LogRecord> records = [];

  LogCapture() {
    logger.level = Level.ALL;
    logger.onRecord.listen(records.add);
  }

  /// All messages including error and stack trace text.
  String get text => records
      .map((r) => "${r.level} ${r.message} ${r.error} ${r.stackTrace}")
      .join("\n");

  void expectNoSecret() {
    expect(records, isNotEmpty);
    expect(text, isNot(contains(token)));
    expect(text, isNot(contains(Uri.encodeComponent(token))));
    expect(text, isNot(contains(basicCredentials)));
  }
}

Future<String> tokenFactory() async => token;

/// Fake http client for the negotiate request and the long polling requests.
class FakeHttpClient extends SignalRHttpClient {
  final List<SignalRHttpRequest> requests = [];
  Object? negotiateError;
  int pollCount = 0;

  @override
  Future<SignalRHttpResponse> send(SignalRHttpRequest request) async {
    requests.add(request);
    if (request.method == "POST") {
      if (negotiateError != null) {
        throw negotiateError!;
      }
      return SignalRHttpResponse(200,
          content: json.encode({
            "negotiateVersion": 1,
            "connectionId": "cid",
            "connectionToken": "ctoken",
            "availableTransports": [
              {
                "transport": "LongPolling",
                "transferFormats": ["Text", "Binary"]
              }
            ]
          }));
    }
    if (request.method == "GET") {
      pollCount++;
      // The first poll initializes the connection, the second ends it.
      return pollCount == 1
          ? SignalRHttpResponse(200, content: "")
          : SignalRHttpResponse(204);
    }
    return SignalRHttpResponse(200, content: "");
  }
}

void main() {
  group('Redaction helper -> ', () {
    test('access_token query parameter value is replaced and the rest is kept',
        () {
      final result = redactSecrets(
          "http://host:8080/hub?id=abc&access_token=$token&other=1");
      expect(result,
          "http://host:8080/hub?id=abc&access_token=$redactedMarker&other=1");
    });

    test('access_token as first query parameter is replaced', () {
      expect(redactSecrets("ws://host/hub?access_token=$token"),
          "ws://host/hub?access_token=$redactedMarker");
    });

    test('url encoded access_token is replaced', () {
      final encoded = Uri.encodeComponent("a b/c+d=e");
      expect(redactSecrets("http://h/p?access_token=$encoded&id=1"),
          "http://h/p?access_token=$redactedMarker&id=1");
    });

    test('access_token inside error text is replaced', () {
      final result = redactSecrets(Exception(
          "Connection refused, uri=http://host/hub?id=1&access_token=$token"));
      expect(result, isNot(contains(token)));
      expect(result, contains("http://host/hub?id=1"));
    });

    test('bearer jwt outside an authorization header is replaced completely',
        () {
      final result = redactSecrets("rejected Bearer $jwt by the server");
      expect(result, "rejected Bearer $redactedMarker by the server");
    });

    test('authorization bearer jwt is replaced completely', () {
      expect(redactSecrets("Authorization: Bearer $jwt"),
          "Authorization: $redactedMarker");
    });

    test('basic credential in an authorization header is replaced', () {
      expect(redactSecrets("Authorization: Basic $basicCredentials"),
          "Authorization: $redactedMarker");
    });

    test('authorization credential stops before a sibling key with equals sign',
        () {
      expect(redactSecrets("Authorization: Bearer abc123, Accept=1"),
          "Authorization: $redactedMarker, Accept=1");
    });

    test('authorization credential does not continue into the next line', () {
      expect(redactSecrets("Authorization: Bearer abc123\nnext line visible"),
          "Authorization: $redactedMarker\nnext line visible");
    });

    test('bearer word with a dotted word is unchanged', () {
      expect(redactSecrets("bearer token.expired"), "bearer token.expired");
    });

    test('bearer word with a version number is unchanged', () {
      expect(redactSecrets("Bearer v1.2 is old"), "Bearer v1.2 is old");
    });

    test('authorization word followed by plain text is unchanged', () {
      expect(redactSecrets("Authorization: required for this call"),
          "Authorization: required for this call");
    });

    test('access_token value with a percent escape is replaced completely', () {
      expect(redactSecrets("http://h/?access_token=ab%2Bcd%2Fef&id=1"),
          "http://h/?access_token=$redactedMarker&id=1");
    });

    test('known secret is replaced by its exact value and encoded form', () {
      final redactor = SecretRedactor()..remember("a+b/c=secretvalue");
      final result = redactor.redact(
          "plain a+b/c=secretvalue and ${Uri.encodeComponent("a+b/c=secretvalue")} end");
      expect(result, "plain *** and *** end");
    });

    test('only the newest known secrets are kept after many renewals', () {
      final redactor = SecretRedactor();
      for (var i = 0; i < 100; i++) {
        redactor.remember("renewed-token-value-$i");
        redactor.remember("renewed-token-value-$i");
      }
      expect(redactor.secretCount, SecretRedactor.maxSecrets);
      expect(redactor.redact("a renewed-token-value-99 b"), "a *** b");
      expect(redactor.redact("a renewed-token-value-92 b"), "a *** b");
      expect(redactor.redact("a renewed-token-value-91 b"),
          "a renewed-token-value-91 b");
    });

    test('access_token value ends at a fragment marker', () {
      expect(redactSecrets("http://h/?access_token=$token#frag"),
          "http://h/?access_token=$redactedMarker#frag");
    });

    test('known secret shorter than the minimum is not replaced', () {
      final redactor = SecretRedactor()..remember("abc");
      expect(redactor.redact("abc stays"), "abc stays");
    });

    test('url encoded access_token with encoded equals sign is replaced', () {
      final result =
          redactSecrets("http://h/p%3Fid%3D1%26access_token%3D$token%26x%3D2");
      expect(result, isNot(contains(token)));
      expect(result, contains("%26x%3D2"));
    });

    test('access_token as json key is replaced', () {
      final result = redactSecrets('{"access_token":"$token","id":"1"}');
      expect(result, '{"access_token":"$redactedMarker","id":"1"}');
    });

    test('access_token as map key with single quotes is replaced', () {
      final result = redactSecrets("{'access_token': '$token', 'id': 1}");
      expect(result, "{'access_token': '$redactedMarker', 'id': 1}");
    });

    test('access_token with spaces around the separator is replaced', () {
      expect(redactSecrets("access_token = $token next"),
          "access_token = $redactedMarker next");
      expect(redactSecrets("access_token : $token next"),
          "access_token : $redactedMarker next");
    });

    test('access_token after an opening parenthesis is replaced', () {
      expect(redactSecrets("failed(access_token=$token&id=1)"),
          "failed(access_token=$redactedMarker&id=1)");
    });

    test('access_token before a closing parenthesis keeps the parenthesis', () {
      expect(redactSecrets("x(uri=http://h/?access_token=$token)"),
          "x(uri=http://h/?access_token=$redactedMarker)");
    });

    test('access_token is matched case insensitively', () {
      expect(redactSecrets("http://h/?ACCESS_TOKEN=$token"),
          "http://h/?ACCESS_TOKEN=$redactedMarker");
    });

    test('parameter that only ends with access_token is not changed', () {
      expect(redactSecrets("http://h/?my_access_token=visible"),
          "http://h/?my_access_token=visible");
    });

    test('negotiate authorization credential is replaced completely', () {
      expect(redactSecrets("Authorization: Negotiate YIIabc123def"),
          "Authorization: $redactedMarker");
    });

    test('ntlm authorization credential is replaced completely', () {
      expect(redactSecrets("Authorization: NTLM TlRMTVNTUAABAAAA"),
          "Authorization: $redactedMarker");
    });

    test('digest authorization with parameters is replaced completely', () {
      final result = redactSecrets(
          'Authorization: Digest username="user", realm="r", response="abcdef"');
      expect(result, "Authorization: $redactedMarker");
    });

    test('raw authorization value without scheme is replaced', () {
      expect(redactSecrets("Authorization: rawsecretvalue"),
          "Authorization: $redactedMarker");
    });

    test('bearer credential with a comma is replaced completely', () {
      expect(redactSecrets("Authorization: Bearer SECRET.with,comma"),
          "Authorization: $redactedMarker");
    });

    test('authorization in a printed header map keeps the sibling headers', () {
      final result = redactSecrets(
          "{Authorization: Bearer SECRET.with,comma, X-Test: visible}");
      expect(result, "{Authorization: $redactedMarker, X-Test: visible}");
    });

    test('bearer and basic words in ordinary text are unchanged', () {
      expect(redactSecrets("bearer token expired"), "bearer token expired");
      expect(redactSecrets("Basic authentication failed"),
          "Basic authentication failed");
    });

    test('text without secrets is unchanged', () {
      expect(redactSecrets("http://host/hub?id=abc"), "http://host/hub?id=abc");
      expect(redactSecrets(null), "null");
    });

    test('authorization header value is replaced for any header name casing',
        () {
      final headers = MessageHeaders()
        ..setHeaderValue("authorization", "Basic $basicCredentials")
        ..setHeaderValue("X-Test", "visible");
      final result = redactHeaders(headers);
      expect(result, isNot(contains(basicCredentials)));
      expect(result, contains("visible"));
    });
  });

  group('HttpConnection logging -> ', () {
    test('negotiate and long polling do not log the access token', () async {
      final capture = LogCapture();
      final client = FakeHttpClient();
      final connection = HttpConnection(
          "http://example.test:5000/hub?access_token=$token",
          options: HttpConnectionOptions(
              httpClient: client,
              logger: capture.logger,
              accessTokenFactory: tokenFactory));
      await connection.start(transferFormat: TransferFormat.Text);
      await connection.stop();

      // The token still goes over the wire, only the log output is redacted.
      expect(client.requests.first.headers!.getHeaderValue("Authorization"),
          "Bearer $token");
      capture.expectNoSecret();
      expect(capture.text, contains("example.test:5000/hub/negotiate"));
      expect(capture.text, contains("polling: http://example.test:5000/hub"));
    });

    test('failed negotiate does not log the access token from the error text',
        () async {
      final capture = LogCapture();
      final client = FakeHttpClient()
        ..negotiateError = Exception(
            "ClientException: refused, uri=http://example.test:5000/hub/negotiate?access_token=$token");
      final connection = HttpConnection("http://example.test:5000/hub",
          options: HttpConnectionOptions(
              httpClient: client,
              logger: capture.logger,
              accessTokenFactory: tokenFactory));
      await expectLater(connection.start(transferFormat: TransferFormat.Text),
          throwsA(anything));

      capture.expectNoSecret();
      expect(capture.text, contains("example.test:5000/hub/negotiate"));
    });

    test('error text of a closed connection does not log the access token',
        () async {
      final capture = LogCapture();
      final transport = _FakeTransport();
      final connection = HttpConnection(
          "http://example.test:5000/hub?access_token=$token",
          options: HttpConnectionOptions(
              logger: capture.logger,
              transport: transport,
              skipNegotiation: false,
              httpClient: FakeHttpClient()));
      await connection.start(transferFormat: TransferFormat.Text);
      transport.onClose!(
          error: GeneralError(
              "socket closed, uri=http://example.test:5000/hub?access_token=$token"));

      capture.expectNoSecret();
      expect(capture.text, contains("example.test:5000/hub"));
    });
  });

  group('Error text handed to the application -> ', () {
    test('start error from a failed transport keeps transport and cause',
        () async {
      final client = _FailingGetClient(
          "refused errno = 61, uri=http://example.test:5000/hub?id=1&access_token=$token");
      final connection = HttpConnection("http://example.test:5000/hub",
          options: HttpConnectionOptions(
              httpClient: client, accessTokenFactory: tokenFactory));
      Object? error;
      try {
        await connection.start(transferFormat: TransferFormat.Text);
      } catch (e) {
        error = e;
      }
      expect(
          error.toString(),
          contains(
              "Unable to connect to the server with any of the available transports."));
      expect(error.toString(), contains("LongPolling failed:"));
      expect(error.toString(), contains("errno = 61"));
      expect(error.toString(), contains("example.test:5000/hub?id=1"));
      expect(error.toString(), isNot(contains(token)));
    });

    test('token value in free error text is removed by its exact value',
        () async {
      final client = _FailingGetClient("refused for token $token on poll");
      final connection = HttpConnection("http://example.test:5000/hub",
          options: HttpConnectionOptions(
              httpClient: client, accessTokenFactory: tokenFactory));
      Object? error;
      try {
        await connection.start(transferFormat: TransferFormat.Text);
      } catch (e) {
        error = e;
      }
      // The long polling transport (own factory call) and the connection
      // both know the token value.
      expect(error.toString(), contains("refused for token"));
      expect(error.toString(), isNot(contains(token)));
    });

    test('access token from a negotiate redirect is removed from error text',
        () async {
      final client = _FailingGetClient("poll failed for redirect-token-abcdef",
          negotiateAccessToken: "redirect-token-abcdef");
      final connection = HttpConnection("http://example.test:5000/hub",
          options: HttpConnectionOptions(httpClient: client));
      Object? error;
      try {
        await connection.start(transferFormat: TransferFormat.Text);
      } catch (e) {
        error = e;
      }
      expect(error.toString(), contains("poll failed for"));
      expect(error.toString(), isNot(contains("redirect-token-abcdef")));
    });

    test('jwt from the token factory is removed from log output and error text',
        () async {
      final capture = LogCapture();
      final client = _FailingGetClient("poll refused, credential $jwt");
      final connection = HttpConnection("http://example.test:5000/hub",
          options: HttpConnectionOptions(
              httpClient: client,
              logger: capture.logger,
              accessTokenFactory: () async => jwt));
      Object? error;
      try {
        await connection.start(transferFormat: TransferFormat.Text);
      } catch (e) {
        error = e;
      }
      expect(client.requests.last.headers!.getHeaderValue("Authorization"),
          "Bearer $jwt");
      expect(error.toString(), contains("poll refused"));
      expect(error.toString(), isNot(contains(jwt)));
      expect(capture.text, isNot(contains(jwt)));
      expect(capture.text, isNot(contains(jwt.split(".")[1])));
    });

    test('long polling close error keeps the cause without the token',
        () async {
      final client = _FailingPollClient(
          "SocketException: reset errno = 54, uri=http://example.test:5000/hub?access_token=$token");
      final transport = LongPollingTransport(client, tokenFactory, null, false);
      final closed = Completer<Exception?>();
      transport.onClose = ({Exception? error}) => closed.complete(error);
      await transport.connect(
          "http://example.test:5000/hub?id=abc", TransferFormat.Text);
      final error = await closed.future.timeout(const Duration(seconds: 5));
      expect(error.toString(), contains("errno = 54"));
      expect(error.toString(), contains("example.test:5000/hub"));
      expect(error.toString(), isNot(contains(token)));
    });

    test(
        'stopConnection error while connecting keeps the cause without the token',
        () async {
      final transport = _FakeTransport();
      final connection = HttpConnection("http://example.test:5000/hub",
          options: HttpConnectionOptions(
              httpClient: FakeHttpClient(), transport: transport));
      final completer = Completer<void>();
      transport.onConnect = () => completer.future;
      final start = connection.start(transferFormat: TransferFormat.Text);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      Object? error;
      try {
        transport.onClose!(
            error: GeneralError(
                "closed errno = 32, uri=http://example.test:5000/hub?access_token=$token"));
      } catch (e) {
        error = e;
      }
      completer.complete();
      await start;
      expect(error.toString(), contains("errno = 32"));
      expect(error.toString(), isNot(contains(token)));
    });
  });

  group('WebSupportingHttpClient logging -> ', () {
    test(
        'http send line does not log the authorization header or the token url',
        () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((request) async {
        await request.drain();
        request.response.statusCode = 200;
        request.response.headers.contentType = ContentType.json;
        await request.response.close();
      });
      addTearDown(() => server.close(force: true));

      final capture = LogCapture();
      final client = WebSupportingHttpClient(capture.logger);
      final headers = MessageHeaders()
        ..setHeaderValue("Authorization", "Bearer $token");
      final url = "http://127.0.0.1:${server.port}/hub?access_token=$token";
      await client.send(SignalRHttpRequest(
          method: "GET", url: url, headers: headers, content: ""));

      capture.expectNoSecret();
      expect(capture.text, contains("127.0.0.1:${server.port}/hub"));
    });
  });

  group('WebSocketTransport logging -> ', () {
    test('connect does not log the access token of the websocket url',
        () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final sockets = <WebSocket>[];
      final accepted = Completer<void>();
      server.listen((request) async {
        sockets.add(await WebSocketTransformer.upgrade(request));
        accepted.complete();
      });
      addTearDown(() async {
        for (final s in sockets) {
          await s.close();
        }
        await server.close(force: true);
      });

      final capture = LogCapture();
      final transport = WebSocketTransport(tokenFactory, capture.logger, false);
      await transport.connect(
          "http://127.0.0.1:${server.port}/hub?id=abc", TransferFormat.Text);
      await accepted.future.timeout(const Duration(seconds: 5));
      await transport.stop();

      capture.expectNoSecret();
      expect(capture.text, contains("127.0.0.1:${server.port}/hub?id=abc"));
      final connected =
          capture.records.firstWhere((r) => r.message.contains("connected to"));
      expect(connected.level, Level.INFO);
    });
  });

  group('WebSocket upgrade refused -> ', () {
    test('package log records do not contain the token when the upgrade fails',
        () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((request) async {
        request.response.statusCode = 401;
        await request.response.close();
      });
      addTearDown(() => server.close(force: true));

      final capture = LogCapture();
      final done = Completer<void>();
      // The error of the WebSocket client is passed on unchanged and reaches
      // the zone handler. It is not part of what this test checks.
      runZonedGuarded(() async {
        final connection = HttpConnection("http://127.0.0.1:${server.port}/hub",
            options: HttpConnectionOptions(
                skipNegotiation: true,
                transport: HttpTransportType.WebSockets,
                logger: capture.logger,
                accessTokenFactory: tokenFactory));
        try {
          await connection.start(transferFormat: TransferFormat.Text);
        } catch (_) {}
        await Future<void>.delayed(const Duration(milliseconds: 500));
        done.complete();
      }, (error, stack) {});
      await done.future;

      capture.expectNoSecret();
      expect(capture.text, contains("127.0.0.1:${server.port}/hub"));
    });
  });

  group('WebSocketTransport bare token in logged error text -> ', () {
    test('error from onReceive that quotes the bare token is not logged',
        () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final sockets = <WebSocket>[];
      server.listen((request) async {
        final socket = await WebSocketTransformer.upgrade(request);
        sockets.add(socket);
        socket.add("hello");
      });
      addTearDown(() async {
        for (final s in sockets) {
          await s.close();
        }
        await server.close(force: true);
      });

      final capture = LogCapture();
      final transport = WebSocketTransport(tokenFactory, capture.logger, false);
      final received = Completer<void>();
      transport.onReceive = (data) {
        received.complete();
        throw Exception("rejected message for credential $token");
      };
      await transport.connect(
          "http://127.0.0.1:${server.port}/hub?id=abc", TransferFormat.Text);
      await received.future.timeout(const Duration(seconds: 5));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await transport.stop();

      expect(capture.text, contains("error calling onReceive"));
      expect(capture.text, contains("rejected message for credential"));
      capture.expectNoSecret();
    });
  });

  group('ServerSentEventsTransport logging -> ', () {
    test('connect does not log the access token of the sse url', () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final responses = <HttpResponse>[];
      final accepted = Completer<void>();
      server.listen((request) async {
        request.response.headers.contentType =
            ContentType("text", "event-stream");
        request.response.bufferOutput = false;
        responses.add(request.response);
        request.response.write(":\n\n");
        await request.response.flush();
        accepted.complete();
      });
      addTearDown(() async {
        for (final r in responses) {
          await r.close();
        }
        await server.close(force: true);
      });

      final capture = LogCapture();
      final transport = ServerSentEventsTransport(
          FakeHttpClient(), tokenFactory, capture.logger, false);
      await transport.connect(
          "http://127.0.0.1:${server.port}/hub?id=abc", TransferFormat.Text);
      await accepted.future.timeout(const Duration(seconds: 5));
      await transport.stop();

      capture.expectNoSecret();
      expect(capture.text, contains("127.0.0.1:${server.port}/hub?id=abc"));
    });
  });

  group('ServerSentEventsTransport token that ends the pattern early -> ', () {
    test('url log does not contain the tail of a token with quote characters',
        () async {
      // Uri.encodeComponent keeps the characters ' ( ) unchanged. The
      // access_token pattern stops at them, only the remembered value covers
      // the rest of the token.
      const oddToken = "HEADPART'TAILPART(more)ENDPART";
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final responses = <HttpResponse>[];
      final accepted = Completer<void>();
      server.listen((request) async {
        request.response.headers.contentType =
            ContentType("text", "event-stream");
        request.response.bufferOutput = false;
        responses.add(request.response);
        request.response.write(":\n\n");
        await request.response.flush();
        accepted.complete();
      });
      addTearDown(() async {
        for (final r in responses) {
          await r.close();
        }
        await server.close(force: true);
      });

      final capture = LogCapture();
      final transport = ServerSentEventsTransport(
          FakeHttpClient(), () async => oddToken, capture.logger, false);
      await transport.connect(
          "http://127.0.0.1:${server.port}/hub?id=abc", TransferFormat.Text);
      await accepted.future.timeout(const Duration(seconds: 5));
      await transport.stop();

      expect(capture.text, contains("connected to"));
      expect(capture.text, contains("127.0.0.1:${server.port}/hub?id=abc"));
      expect(capture.text, isNot(contains("TAILPART")));
      expect(capture.text, isNot(contains("ENDPART")));
    });
  });

  group('LongPollingTransport bare token in logged error text -> ', () {
    test('failing poll that quotes the bare token is not logged', () async {
      final capture = LogCapture();
      final client = _FailingPollClient("poll refused for credential $token");
      final transport =
          LongPollingTransport(client, tokenFactory, capture.logger, false);
      final closed = Completer<void>();
      transport.onClose = ({Exception? error}) {
        if (!closed.isCompleted) closed.complete();
      };
      await transport.connect(
          "http://example.test:5000/hub?id=abc", TransferFormat.Text);
      await closed.future.timeout(const Duration(seconds: 5));

      expect(capture.text, contains("Firing onclose event. Error:"));
      expect(capture.text, contains("poll refused for credential"));
      capture.expectNoSecret();
    });
  });

  group('LongPollingTransport logging -> ', () {
    test('connect, poll and stop do not log the access token', () async {
      final capture = LogCapture();
      final client = FakeHttpClient();
      final transport =
          LongPollingTransport(client, tokenFactory, capture.logger, false);
      final closed = Completer<void>();
      transport.onClose = ({Exception? error}) {
        if (!closed.isCompleted) closed.complete();
      };
      await transport.connect(
          "http://example.test:5000/hub?id=abc&access_token=$token",
          TransferFormat.Text);
      await closed.future.timeout(const Duration(seconds: 5));
      await transport.stop();

      expect(client.requests.first.headers!.getHeaderValue("Authorization"),
          "Bearer $token");
      capture.expectNoSecret();
      expect(capture.text,
          contains("polling: http://example.test:5000/hub?id=abc"));
    });

    test('send does not log the access token', () async {
      final capture = LogCapture();
      final client = FakeHttpClient();
      final transport =
          LongPollingTransport(client, tokenFactory, capture.logger, false);
      await transport.connect(
          "http://example.test:5000/hub?id=abc&access_token=$token",
          TransferFormat.Text);
      await transport.send("data");
      await transport.stop();

      capture.expectNoSecret();
    });
  });
}

class _FakeTransport implements ITransport {
  @override
  OnClose? onClose;

  @override
  OnReceive? onReceive;

  Future<void> Function()? onConnect;

  @override
  Future<void> connect(String? url, TransferFormat transferFormat) async {
    await onConnect?.call();
  }

  @override
  Future<void> send(Object data) async {}

  @override
  Future<void> stop() async {}
}

/// First poll succeeds, the next poll throws.
class _FailingPollClient extends SignalRHttpClient {
  final String message;
  int count = 0;

  _FailingPollClient(this.message);

  @override
  Future<SignalRHttpResponse> send(SignalRHttpRequest request) async {
    count++;
    if (count == 1) {
      return SignalRHttpResponse(200, content: "");
    }
    throw Exception(message);
  }
}

/// Negotiates like [FakeHttpClient] but fails every GET.
class _FailingGetClient extends FakeHttpClient {
  final String message;
  final String? negotiateAccessToken;

  _FailingGetClient(this.message, {this.negotiateAccessToken});

  @override
  Future<SignalRHttpResponse> send(SignalRHttpRequest request) async {
    if (request.method == "GET") {
      requests.add(request);
      throw Exception(message);
    }
    final response = await super.send(request);
    if (negotiateAccessToken == null) {
      return response;
    }
    final body = json.decode(response.content as String) as Map;
    body["accessToken"] = negotiateAccessToken;
    return SignalRHttpResponse(200, content: json.encode(body));
  }
}
