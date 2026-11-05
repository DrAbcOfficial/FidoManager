using System.Globalization;
using Fido2.Core.Ctap2;
using Fido2.Core.Sessions;

namespace Fido2.Cli;

internal static class PinCommand
{
    public static async Task<int> RunAsync(string[] args, CommandLine line, CancellationToken cancellationToken)
    {
        string subcommand = args.Length > 0
            ? args[0]
            : throw new UsageException("pin needs a subcommand: state, set or change.");
        if (args.Length > 1)
        {
            throw new UsageException($"unexpected argument '{args[1]}'.");
        }

        return subcommand switch
        {
            "state" => await StateAsync(line, cancellationToken).ConfigureAwait(false),
            "set" => await SetAsync(line, cancellationToken).ConfigureAwait(false),
            "change" => await ChangeAsync(line, cancellationToken).ConfigureAwait(false),
            _ => throw new UsageException($"unknown pin subcommand '{subcommand}'."),
        };
    }

    private static async Task<int> StateAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly(Options.Global);
        using AuthenticatorSession session =
            await DeviceConnector.OpenAsync(line, cancellationToken).ConfigureAwait(false);
        PinState state = await session.GetPinStateAsync(cancellationToken, new TouchPrompt()).ConfigureAwait(false);

        if (line.Has(Options.Json))
        {
            Output.Json(new PinJson(state.IsSet, state.RetriesRemaining));
            return ExitCodes.Ok;
        }

        Console.WriteLine(state.IsSet
            ? $"PIN set · {state.RetriesRemaining?.ToString(CultureInfo.InvariantCulture) ?? "?"} retries remaining"
            : "No PIN set.");
        return ExitCodes.Ok;
    }

    private static async Task<int> SetAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly([.. Options.Global, "new"]);
        using AuthenticatorSession session =
            await DeviceConnector.OpenAsync(line, cancellationToken).ConfigureAwait(false);

        PinState state = await session.GetPinStateAsync(cancellationToken, new TouchPrompt()).ConfigureAwait(false);
        if (state.IsSet)
        {
            throw new CliException("a PIN is already set — use 'fido2 pin change'.");
        }

        string pin = PinSource.New(line);
        await session.SetPinAsync(pin, cancellationToken, new TouchPrompt()).ConfigureAwait(false);
        Console.Error.WriteLine("PIN set.");
        return ExitCodes.Ok;
    }

    private static async Task<int> ChangeAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly([.. Options.Global, "new"]);
        using AuthenticatorSession session =
            await DeviceConnector.OpenAsync(line, cancellationToken).ConfigureAwait(false);

        string current = PinSource.Require(line, "Current PIN");
        string next = PinSource.New(line);
        await session.ChangePinAsync(current, next, cancellationToken, new TouchPrompt()).ConfigureAwait(false);
        Console.Error.WriteLine("PIN changed.");
        return ExitCodes.Ok;
    }
}
