namespace Fido2.Core.Transports;

/// <summary>Transport-level failure (device open, read/write, protocol framing). 
/// Separated from <see cref="CtapException"/> which is an authenticator-reported error.</summary>
public sealed class TransportException : Exception
{
    public TransportException(string message) : base(message) { }

    public TransportException(string message, Exception innerException)
        : base(message, innerException) { }
}
