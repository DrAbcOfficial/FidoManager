namespace Fido2.Cli.Tests;

/// <summary>
/// The parser decides whether "fido2 --json creds list" runs or silently eats the command
/// name, so the flag/value distinction is pinned here.
/// </summary>
public class CommandLineTests
{
    [Fact]
    public void FlagsDoNotSwallowPositionals()
    {
        CommandLine line = CommandLine.Parse(["--json", "creds", "list", "--pin", "123456"]);

        Assert.Equal(new[] { "creds", "list" }, line.Positionals);
        Assert.True(line.Has(Options.Json));
        Assert.Equal("123456", line.Value(Options.Pin));
        line.EnsureOnly(Options.Global); // must not throw
    }

    [Fact]
    public void EqualsFormCarriesValuesWithSpaces()
    {
        CommandLine line = CommandLine.Parse(["creds", "list", "--pin=12 34", "--index=2"]);

        Assert.Equal("12 34", line.Value(Options.Pin));
        Assert.Equal(2, line.IntValue("index"));
    }

    [Fact]
    public void UnknownOptionsAreRejected()
    {
        CommandLine line = CommandLine.Parse(["devices", "--bogus"]);

        UsageException error = Assert.Throws<UsageException>(() => line.EnsureOnly(Options.Global));
        Assert.Contains("--bogus", error.Message);
    }

    [Fact]
    public void DoubleDashEndsOptionParsing()
    {
        CommandLine line = CommandLine.Parse(["creds", "--", "--pin", "x"]);

        Assert.Equal(new[] { "creds", "--pin", "x" }, line.Positionals);
        Assert.False(line.Has(Options.Pin));
    }

    [Fact]
    public void InvalidIntegerIsAUsageError()
    {
        CommandLine line = CommandLine.Parse(["--index", "two"]);

        Assert.Throws<UsageException>(() => line.IntValue("index"));
    }

    [Fact]
    public void MissingValueIsAUsageError()
    {
        CommandLine line = CommandLine.Parse(["--out"]);

        Assert.Throws<UsageException>(() => line.RequireValue("out"));
    }

    [Fact]
    public void ShortHelpAndVersionAreRecognised()
    {
        Assert.True(CommandLine.Parse(["-h"]).Has("help"));
        Assert.True(CommandLine.Parse(["-V"]).Has("version"));
    }

    [Fact]
    public void PinOptionIsTakenVerbatim()
    {
        CommandLine line = CommandLine.Parse(["--pin", "123456"]);

        Assert.Equal("123456", PinSource.Require(line, "unused"));
    }
}
