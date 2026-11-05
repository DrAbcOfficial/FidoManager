using System.Text;

namespace Fido2.Cli;

/// <summary>Entry point: wires Ctrl+C to the cancellation token so the authenticator sees a
/// KEEPALIVE_CANCEL, then maps the three outcome classes to exit codes (0 / 1 / 2).</summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            Console.OutputEncoding = Encoding.UTF8;
        }
        catch (Exception)
        {
            // No console attached — leave the default encoding.
        }

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler onCancel = (_, e) =>
        {
            e.Cancel = true; // let the CTAP cancel unwind instead of killing the process
            cancellation.Cancel();
        };
        Console.CancelKeyPress += onCancel;

        try
        {
            return await CliApplication.RunAsync(args, cancellation.Token).ConfigureAwait(false);
        }
        catch (UsageException ex)
        {
            Console.Error.WriteLine($"fido2: {ex.Message}");
            Console.Error.WriteLine("Try 'fido2 --help'.");
            return ExitCodes.Usage;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("canceled.");
            return ExitCodes.Error;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"fido2: {ex.Message}");
            return ExitCodes.Error;
        }
        finally
        {
            Console.CancelKeyPress -= onCancel;
        }
    }
}
