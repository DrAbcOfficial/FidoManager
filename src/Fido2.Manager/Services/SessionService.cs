using Fido2.Core.Ctap2;
using Fido2.Core.Sessions;
using Fido2.Core.Transports;

namespace Fido2.Manager.Services;

/// <summary>
/// Owns the currently-open authenticator session and the remembered PIN (design doc §6):
/// in-memory for this window only, never written to disk; dropped on rescan (the key may
/// have been swapped) and on any PIN-related refusal so a stale PIN cannot burn retries.
/// </summary>
public sealed class SessionService
{
    private readonly object _gate = new();
    private AuthenticatorSession? _session;
    private string? _pinCache;

    public AuthenticatorSession? Current
    {
        get { lock (_gate) { return _session; } }
    }

    public bool HasDevice
    {
        get { lock (_gate) { return _session is not null; } }
    }

    public string? CachedPin
    {
        get { lock (_gate) { return _pinCache; } }
    }

    /// <summary>Closes the current device and clears the PIN cache (rescan semantics).</summary>
    public void CloseDevice()
    {
        AuthenticatorSession? stale;
        lock (_gate)
        {
            stale = _session;
            _session = null;
            _pinCache = null;
        }
        stale?.Dispose();
    }

    public void ReplaceSession(AuthenticatorSession session)
    {
        AuthenticatorSession? stale;
        lock (_gate)
        {
            stale = _session;
            _session = session;
            _pinCache = null;
        }
        stale?.Dispose();
    }

    public void RememberPin(string pin)
    {
        lock (_gate) { _pinCache = pin; }
    }

    /// <summary>Drops the remembered PIN after the device rejected it (0x31/0x33/0x34/0x36 …).</summary>
    public void ClearPin()
    {
        lock (_gate) { _pinCache = null; }
    }

    public void ClearPinOnError(Exception exception)
    {
        if (exception is CtapException { IsPinError: true })
        {
            ClearPin();
        }
    }
}
