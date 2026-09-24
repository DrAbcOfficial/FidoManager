namespace Fido2.Core.Transports;

/// <summary>CTAP keep-alive statuses carried over CTAPHID KEEPALIVE / NFCCTAP_GETRESPONSE.</summary>
public enum KeepaliveStatus : byte
{
    Processing = 1,
    UpNeeded = 2,
}
