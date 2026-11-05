using System.Globalization;

namespace Fido2.Cli;

/// <summary>Command dispatch and help. Data goes to stdout, status/prompts to stderr, so
/// <c>fido2 creds export &gt; keys.pub</c> stays clean.</summary>
internal static class CliApplication
{
    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        CommandLine line = CommandLine.Parse(args);

        if (line.Has("version"))
        {
            PrintVersion();
            return ExitCodes.Ok;
        }
        if (line.Has("help"))
        {
            Console.WriteLine(HelpText);
            return ExitCodes.Ok;
        }
        if (line.Positionals.Count == 0)
        {
            Console.WriteLine(HelpText);
            return ExitCodes.Usage;
        }

        string command = line.Positionals[0];
        string[] rest = [.. line.Positionals.Skip(1)];
        return command switch
        {
            "devices" => await DevicesCommand.RunAsync(line, cancellationToken).ConfigureAwait(false),
            "info" => await InfoCommand.RunAsync(line, cancellationToken).ConfigureAwait(false),
            "creds" => await CredentialsCommand.RunAsync(rest, line, cancellationToken).ConfigureAwait(false),
            "ssh" => await CredentialsCommand.ExportAsync(line, cancellationToken).ConfigureAwait(false),
            "pin" => await PinCommand.RunAsync(rest, line, cancellationToken).ConfigureAwait(false),
            "reset" => await ResetCommand.RunAsync(line, cancellationToken).ConfigureAwait(false),
            "help" => ShowHelp(),
            _ => throw new UsageException($"unknown command '{command}'."),
        };
    }

    private static int ShowHelp()
    {
        Console.WriteLine(HelpText);
        return ExitCodes.Ok;
    }

    private static void PrintVersion()
    {
        string version = typeof(CliApplication).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        Console.WriteLine($"fido2 {version}");
    }

    private const string HelpText =
        """
        fido2 — FIDO2 security key manager (command line)

        Usage:
          fido2 <command> [options]

        Commands:
          devices                  List connected authenticators
          info                     Show authenticator capabilities
          creds list               List resident (discoverable) credentials
          creds export             Export resident public keys as OpenSSH sk-* lines
          creds delete --id <hex>  Delete a resident credential
          pin state                Show whether a PIN is set and retries remaining
          pin set --new <pin>      Set a PIN on a key that has none
          pin change --new <pin>   Change the PIN (--pin supplies the current one)
          reset                    Factory-reset the key (wipes everything)
          ssh                      Alias for 'creds export'

        Options:
          --device <index|name>    Choose an authenticator (default: the only one found)
          --pin <pin>              Current PIN (prefer --pin-stdin or the prompt)
          --pin-stdin              Read the current PIN from the first line of stdin
          --json                   Machine-readable output
          --out <file>             Write exported keys to a file (creds export)
          --index <n>              Export only the credential at list index n
          --id <hex>               Select one credential by (a prefix of) its id
          --force                  Overwrite an existing --out file
          --yes                    Skip the destructive-operation confirmation
          -h, --help               Show this help
          -V, --version            Show the version

        Exit codes:
          0  success
          1  failure
          2  usage error

        Notes:
          * USB-HID access usually needs an elevated terminal (run as administrator).
          * Only public keys are exported; nothing secret leaves the authenticator.
          * 'creds export' writes one '<type> <base64> <comment>' line per credential,
            exactly the format ssh-keygen produces for ed25519-sk / ecdsa-sk keys.
        """;
}
