/// Base class for errors this SDK raises about the ledger or its data, as
/// opposed to programming errors (which are [ArgumentError]s and
/// [StateError]s).
class ActiveledgerException implements Exception {
  ActiveledgerException(this.message);

  final String message;

  @override
  String toString() => 'ActiveledgerException: $message';
}

/// A key type was requested whose implementation is not present in this
/// process - Falcon-512 without the `activeledger_falcon` add-on.
class KeyTypeUnavailableException extends ActiveledgerException {
  KeyTypeUnavailableException(super.message);

  @override
  String toString() => 'KeyTypeUnavailableException: $message';
}

/// The node answered with a non-2xx HTTP status.
///
/// Note that a transaction the ledger REJECTS is still HTTP 200; that case
/// is reported through `LedgerResponse.errors`, not by this exception.
class LedgerHttpException extends ActiveledgerException {
  LedgerHttpException(this.statusCode, this.body)
    : super('Ledger responded with HTTP $statusCode');

  final int statusCode;
  final String body;

  @override
  String toString() => 'LedgerHttpException: HTTP $statusCode: $body';
}

/// Onboarding did not produce an identity.
class OnboardException extends ActiveledgerException {
  OnboardException(super.message, this.response);

  /// The ledger's decoded response, for diagnosis.
  final Object? response;

  @override
  String toString() => 'OnboardException: $message';
}
