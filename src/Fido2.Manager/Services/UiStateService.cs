using Microsoft.UI.Dispatching;

namespace Fido2.Manager.Services;

/// <summary>Global status bar / busy state. Events are marshalled to the UI thread once,
/// here — view models run device I/O on worker threads and must not care about marshalling.</summary>
public sealed class UiStateService
{
    private DispatcherQueue? _dispatcher;
    private bool _isBusy;
    private string _status = Localization.Get("StatusReady");
    private bool _isError;

    public event Action? Changed;

    public void Initialize(DispatcherQueue dispatcher) => _dispatcher = dispatcher;

    public bool IsBusy
    {
        get => _isBusy;
        set => Set(ref _isBusy, value);
    }

    public string Status
    {
        get => _status;
        set => Set(ref _status, value);
    }

    public bool IsError
    {
        get => _isError;
        set => Set(ref _isError, value);
    }

    public void SetMessage(string message) => (Status, IsError) = (message, false);

    public void SetError(string message) => (Status, IsError) = (message, true);

    private void Set<T>(ref T field, T value)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }
        field = value;
        RaiseChanged();
    }

    private void RaiseChanged()
    {
        var dispatcher = _dispatcher;
        if (dispatcher is null || dispatcher.HasThreadAccess)
        {
            Changed?.Invoke();
        }
        else
        {
            dispatcher.TryEnqueue(() => Changed?.Invoke());
        }
    }
}
