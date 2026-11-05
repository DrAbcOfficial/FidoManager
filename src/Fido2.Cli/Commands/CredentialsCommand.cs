using System.Text;
using Fido2.Core.Credentials;
using Fido2.Core.Ctap2;
using Fido2.Core.Sessions;

namespace Fido2.Cli;

internal static class CredentialsCommand
{
    private static readonly string[] ExportOptions = [.. Options.Global, "out", "index", "id", "all", "force"];

    public static async Task<int> RunAsync(string[] args, CommandLine line, CancellationToken cancellationToken)
    {
        string subcommand = args.Length > 0
            ? args[0]
            : throw new UsageException("creds needs a subcommand: list, export or delete.");
        if (args.Length > 1)
        {
            throw new UsageException($"unexpected argument '{args[1]}'.");
        }

        return subcommand switch
        {
            "list" or "ls" => await ListAsync(line, cancellationToken).ConfigureAwait(false),
            "export" => await ExportAsync(line, cancellationToken).ConfigureAwait(false),
            "delete" or "rm" => await DeleteAsync(line, cancellationToken).ConfigureAwait(false),
            _ => throw new UsageException($"unknown creds subcommand '{subcommand}'."),
        };
    }

    /// <summary>Enumerates resident credentials (PIN required) and prints a table or JSON.</summary>
    private static async Task<int> ListAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly(Options.Global);

        using AuthenticatorSession session =
            await DeviceConnector.OpenAsync(line, cancellationToken).ConfigureAwait(false);
        EnsureCredentialManagement(session);
        string pin = PinSource.Require(line, "PIN to read resident credentials");

        CredsMetadata metadata = await session
            .GetCredentialMetadataAsync(pin, cancellationToken, new TouchPrompt()).ConfigureAwait(false);
        IReadOnlyList<ResidentCredential> credentials = await session
            .ListCredentialsAsync(pin, cancellationToken, new TouchPrompt()).ConfigureAwait(false);

        if (line.Has(Options.Json))
        {
            Output.Json(credentials.Select(ToJson).ToArray());
            return ExitCodes.Ok;
        }

        if (credentials.Count == 0)
        {
            Console.Error.WriteLine("No resident credentials.");
            return ExitCodes.Ok;
        }

        var rows = new List<string[]> { new[] { "RP", "USER", "KEY", "CREDENTIAL ID" } };
        foreach (ResidentCredential credential in credentials)
        {
            rows.Add(
            [
                Output.Truncate(credential.RpId, 28),
                Output.Truncate(credential.BestUserName, 24),
                KeyLabel(credential),
                Output.Truncate(credential.CredentialIdHex, 32),
            ]);
        }
        Output.Table(rows);

        int exportable = credentials.Count(credential => credential.HasSshPublicKey);
        string capacity = metadata.MaxRemaining is { } free
            ? $"{metadata.Existing} stored · {free} free"
            : $"{metadata.Existing} stored";
        Console.Error.WriteLine($"{capacity} · {exportable} exportable as OpenSSH key(s).");
        return ExitCodes.Ok;
    }

    /// <summary>
    /// Exports public keys as OpenSSH <c>sk-*</c> lines. With no selector every exportable
    /// credential is written; <c>--index</c>/<c>--id</c> narrow it down and turn a missing
    /// public key into an error instead of a skipped row.
    /// </summary>
    public static async Task<int> ExportAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly(ExportOptions);

        string? outArgument = line.Value("out");
        string? outputPath = outArgument is null ? null : Path.GetFullPath(outArgument);
        if (outputPath is not null)
        {
            if (Directory.Exists(outputPath))
            {
                throw new UsageException($"--out '{outArgument}' is a directory.");
            }
            if (File.Exists(outputPath) && !line.Has("force"))
            {
                throw new CliException($"{outputPath} already exists — pass --force to overwrite.");
            }
        }

        using AuthenticatorSession session =
            await DeviceConnector.OpenAsync(line, cancellationToken).ConfigureAwait(false);
        EnsureCredentialManagement(session);
        string pin = PinSource.Require(line, "PIN to read resident credentials");

        IReadOnlyList<ResidentCredential> credentials = await session
            .ListCredentialsAsync(pin, cancellationToken, new TouchPrompt()).ConfigureAwait(false);
        IReadOnlyList<ResidentCredential> selected = SelectCredentials(credentials, line);
        bool explicitSelection = line.Has("index") || line.Has("id");

        var exported = new List<(ResidentCredential Credential, string Line, string Fingerprint)>();
        foreach (ResidentCredential credential in selected)
        {
            if (OpenSshPublicKey.TryFormat(credential, out string sshLine)
                && OpenSshPublicKey.TryGetFingerprint(credential.PublicKey, out string fingerprint))
            {
                exported.Add((credential, sshLine, fingerprint));
            }
            else if (explicitSelection)
            {
                string reason = credential.PublicKey is null
                    ? "the key did not return a public key"
                    : $"unsupported key type {credential.PublicKey.AlgorithmName}";
                throw new CliException($"credential {credential.CredentialIdHex}: {reason}.");
            }
            else
            {
                Console.Error.WriteLine(
                    $"warning: skipped {credential.RpId} / {credential.BestUserName}: no exportable public key.");
            }
        }

        if (exported.Count == 0)
        {
            throw new CliException(
                "no credential could be exported — this authenticator does not return public keys for its resident credentials.");
        }

        if (outputPath is not null)
        {
            File.WriteAllText(
                outputPath,
                string.Concat(exported.Select(item => item.Line + "\n")),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            Console.Error.WriteLine($"wrote {exported.Count} key(s) to {outputPath}");
        }

        if (line.Has(Options.Json))
        {
            Output.Json(new ExportJson(
                outputPath,
                exported.Count,
                [.. exported.Select(item => ToJson(item.Credential))]));
            return ExitCodes.Ok;
        }

        if (outputPath is null)
        {
            foreach (var item in exported)
            {
                Console.WriteLine(item.Line);
            }
        }
        return ExitCodes.Ok;
    }

    private static async Task<int> DeleteAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly([.. Options.Global, "id", "yes"]);

        string id = line.RequireValue("id");
        using AuthenticatorSession session =
            await DeviceConnector.OpenAsync(line, cancellationToken).ConfigureAwait(false);
        EnsureCredentialManagement(session);
        string pin = PinSource.Require(line, "PIN to read resident credentials");
        IReadOnlyList<ResidentCredential> credentials = await session
            .ListCredentialsAsync(pin, cancellationToken, new TouchPrompt()).ConfigureAwait(false);

        ResidentCredential credential = FindById(credentials, id);
        if (!line.Has("yes"))
        {
            bool confirmed = Prompt.Confirm(
                $"Delete the credential for {credential.RpId} / {credential.BestUserName}? This cannot be undone.");
            if (!confirmed)
            {
                Console.Error.WriteLine("canceled.");
                return ExitCodes.Ok;
            }
        }

        await session.DeleteCredentialAsync(
            pin, Convert.FromHexString(credential.CredentialIdHex), cancellationToken, new TouchPrompt())
            .ConfigureAwait(false);
        Console.Error.WriteLine($"deleted {credential.CredentialIdHex}.");
        return ExitCodes.Ok;
    }

    private static void EnsureCredentialManagement(AuthenticatorSession session)
    {
        if (!session.Options.SupportsCredentialManagement)
        {
            throw new CliException("this authenticator does not support credential management.");
        }
    }

    private static IReadOnlyList<ResidentCredential> SelectCredentials(
        IReadOnlyList<ResidentCredential> credentials, CommandLine line)
    {
        int? index = line.IntValue("index");
        string? id = line.Value("id");
        if (index is not null && id is not null)
        {
            throw new UsageException("use either --index or --id, not both.");
        }
        if (line.Has("all") && (index is not null || id is not null))
        {
            throw new UsageException("--all cannot be combined with --index/--id.");
        }
        if (id is not null)
        {
            return [FindById(credentials, id)];
        }
        if (index is not null)
        {
            return index >= 0 && index < credentials.Count
                ? [credentials[index.Value]]
                : throw new UsageException($"--index {index} is out of range (0..{credentials.Count - 1}).");
        }
        return credentials;
    }

    /// <summary>Matches a full credential id or an unambiguous prefix, ignoring : and -.</summary>
    private static ResidentCredential FindById(IReadOnlyList<ResidentCredential> credentials, string raw)
    {
        string wanted = raw.Trim().Replace(":", "").Replace("-", "").ToLowerInvariant();
        if (wanted.Length == 0 || !wanted.All(char.IsAsciiHexDigit))
        {
            throw new UsageException("--id expects a hexadecimal credential id.");
        }

        var matches = credentials
            .Where(credential => credential.CredentialIdHex.StartsWith(wanted, StringComparison.Ordinal))
            .ToList();
        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new CliException($"no resident credential matches id {raw}."),
            _ => throw new CliException($"{matches.Count} credentials match id {raw} — use more characters."),
        };
    }

    private static string KeyLabel(ResidentCredential credential) => credential.PublicKey switch
    {
        null => "-",
        { SupportsOpenSsh: true } key => key.AlgorithmName,
        var key => $"{key.AlgorithmName} (not SSH)",
    };

    private static CredentialJson ToJson(ResidentCredential credential)
    {
        string? sshLine = OpenSshPublicKey.TryFormat(credential, out string line) ? line : null;
        string? fingerprint = OpenSshPublicKey.TryGetFingerprint(credential.PublicKey, out string value) ? value : null;
        return new CredentialJson(
            RpId: credential.RpId,
            UserName: credential.UserName,
            DisplayName: credential.DisplayName,
            UserIdHex: credential.UserIdHex,
            CredentialIdHex: credential.CredentialIdHex,
            HasPublicKey: credential.PublicKey is not null,
            PublicKeyAlgorithm: credential.PublicKey?.AlgorithmName,
            OpenSshKey: sshLine,
            OpenSshFingerprint: fingerprint,
            Comment: sshLine is null
                ? null
                : OpenSshPublicKey.SuggestComment(credential.RpId, credential.BestUserName));
    }
}
