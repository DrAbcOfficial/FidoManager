using Fido2.Core.Sessions;

namespace Fido2.Cli;

internal static class ResetCommand
{
    public static async Task<int> RunAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly([.. Options.Global, "yes"]);
        using AuthenticatorSession session =
            await DeviceConnector.OpenAsync(line, cancellationToken).ConfigureAwait(false);

        if (!line.Has("yes"))
        {
            bool confirmed = Prompt.Confirm(
                "Factory reset wipes every credential and the PIN, and cannot be undone. Continue?");
            if (!confirmed)
            {
                Console.Error.WriteLine("canceled.");
                return ExitCodes.Ok;
            }
        }

        Console.Error.WriteLine(
            "A reset is only accepted within 10 seconds of power-up — re-insert the key now if needed.");
        await session.ResetAsync(cancellationToken, new TouchPrompt()).ConfigureAwait(false);
        Console.Error.WriteLine("Factory reset complete.");
        return ExitCodes.Ok;
    }
}
