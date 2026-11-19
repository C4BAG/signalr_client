import 'ihub_protocol.dart';

/// Marker that replaces a secret value in log output and in error text.
const String redactedMarker = "***";

// Start of an access_token name: not inside a longer word, but it may follow
// a url encoded character such as %3F.
const String _nameStart = r"(?:(?<![A-Za-z0-9_])|(?<=%[0-9A-Fa-f]{2}))";

// access_token as query parameter, map or JSON key, plain or url encoded.
// The value ends at & %26 # whitespace quotes ) } ; or a comma. Other percent
// escapes belong to the value.
final RegExp _accessToken = RegExp(
    _nameStart +
        r"""(access_token['"]?[ \t]*(?:=|:|%3D)[ \t]*['"]?)""" +
        r"""((?:%(?!26)|[^&\s'";,)}%#])*)""",
    caseSensitive: false);

// Authorization header in text, on one line. The credential runs to the end
// of the header value: to the closing quote when it is quoted, otherwise to
// the end of the line, a closing brace or a single quote. A comma continues a
// value unless a sibling "Name:" or "Name=" entry follows. Digest takes its
// key=value parameters with it, so only "Name:" ends it.
const String _authorizationName =
    r"""(?<![A-Za-z0-9_-])(authorization['"]?[ \t]*[:=][ \t]*)""";
const String _schemes =
    r"(?:Bearer|Basic|Negotiate|NTLM|Digest|Kerberos|Token|OAuth|ApiKey|Hawk|"
    r"Mutual|AWS4-HMAC-SHA256)";
final RegExp _authorizationQuoted = RegExp(
    _authorizationName + r"""(["'])[^\r\n]*?(?=\2)""",
    caseSensitive: false);
final RegExp _authorizationDigest = RegExp(
    _authorizationName +
        r"""(?!["'])Digest(?:"[^"\r\n]*"|[^\r\n}'",]|,(?![ \t]*[A-Za-z][A-Za-z0-9-]*[ \t]*:))+(?<=\S)""",
    caseSensitive: false);
final RegExp _authorizationPlain = RegExp(
    _authorizationName +
        r"""(?!["'])(?:""" +
        _schemes +
        r"""[ \t]+(?:"[^"\r\n]*"|[^\r\n}'",]|,(?![ \t]*[A-Za-z][A-Za-z0-9-]*[ \t]*[:=]))+(?<=\S)""" +
        r"""|[^\s'",}]+(?=[ \t]*(?:[,}'"\r\n]|$)))""",
    caseSensitive: false);

// Bearer or Basic followed by a full JWT (three base64url parts), outside of
// an Authorization header. Other words after Bearer or Basic are plain text.
final RegExp _schemeJwt = RegExp(
    r"\b(Bearer|Basic)([ \t]+)[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    caseSensitive: false);

// Shortest secret that is replaced by its exact value. Shorter values would
// damage ordinary text.
const int _minKnownSecretLength = 6;

/// Returns the text of [value] with secrets replaced by [redactedMarker]:
/// every text in [secrets] (the exact token values, in the forms in which they
/// may appear), the value of every access_token (query parameter, map or JSON
/// key, url encoded or not), the credential of every Authorization header in
/// the text, and a JWT after Bearer or Basic. Host, path and all other text
/// are kept.
///
/// Use it for everything that is written to a logger or put into an error
/// message and that may contain a url, headers or the text of an error.
String redactSecrets(Object? value, {Iterable<String> secrets = const []}) {
  var text = value.toString();
  for (final secret in secrets) {
    text = text.replaceAll(secret, redactedMarker);
  }
  return text
      .replaceAllMapped(_authorizationQuoted,
          (m) => "${m.group(1)}${m.group(2)}$redactedMarker")
      .replaceAllMapped(
          _authorizationDigest, (m) => "${m.group(1)}$redactedMarker")
      .replaceAllMapped(
          _authorizationPlain, (m) => "${m.group(1)}$redactedMarker")
      .replaceAllMapped(_accessToken, (m) => "${m.group(1)}$redactedMarker")
      .replaceAllMapped(
          _schemeJwt, (m) => "${m.group(1)}${m.group(2)}$redactedMarker");
}

/// Remembers the newest access token values of one connection or transport and
/// redacts them by exact value (also url encoded) in addition to the patterns
/// of [redactSecrets].
class SecretRedactor {
  /// Number of token values that are kept. The oldest value is dropped when a
  /// renewed token is added, so a long living transport does not accumulate
  /// every token it ever saw.
  static const int maxSecrets = 8;

  // Newest value last. Each entry holds the value and its url encoded form.
  final List<String> _values = [];
  final Map<String, String> _encoded = {};
  // Texts to replace, longest first.
  List<String> _replacements = const [];

  /// Number of remembered token values.
  int get secretCount => _values.length;

  /// Registers a token value that was handed out by an access token factory.
  void remember(String? secret) {
    if (secret == null ||
        secret.length < _minKnownSecretLength ||
        _values.contains(secret)) {
      return;
    }
    _values.add(secret);
    _encoded[secret] = Uri.encodeComponent(secret);
    if (_values.length > maxSecrets) {
      _encoded.remove(_values.removeAt(0));
    }
    _replacements = {..._values, ..._encoded.values}.toList()
      ..sort((a, b) => b.length.compareTo(a.length));
  }

  String redact(Object? value) => redactSecrets(value, secrets: _replacements);
}

/// Returns the headers in the format of [MessageHeaders.toString] with the value
/// of the Authorization header replaced by [redactedMarker].
String redactHeaders(MessageHeaders? headers) {
  if (headers == null) {
    return "";
  }
  return headers.asMap.entries.map((e) {
    final isAuthorization = e.key.toLowerCase() ==
        MessageHeaders.AuthorizationHeaderName.toLowerCase();
    return '{ ${e.key}: ${isAuthorization ? redactedMarker : redactSecrets(e.value)} }';
  }).join(', ');
}
