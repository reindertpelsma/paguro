using System.Text.Json.Nodes;
using Paguro.Api;
using Paguro.Testing;
using Xunit;

namespace Paguro.Api.Tests;

/// <summary>The pipe client against the fake service.</summary>
public class ClientTests
{
    [Fact]
    public async Task Typed_calls()
    {
        using var srv = FakeServer.Start();
        srv.LoadFixtures(ContractTests.FixturesDir);
        await using var c = await PaguroClient.ConnectAsync(srv.PipeName);
        var st = await c.DistroListAsync();
        Assert.Contains(st.Data.Distributions, d => d.Kind == "image" && d.Size > 1UL << 30);
        // install's first fixture is the dry run (the plan); the .1 fixture has the progress.
        var plan = await c.InstallAsync(new InstallParams { Distro = "fedora", Path = "C:\\x.vhd", DryRun = true });
        Assert.Equal(9, plan.Data.Steps.Count);
        Assert.Equal("install", srv.Calls[^1].Method);
        Assert.Equal("fedora", srv.Calls[^1].Params["distro"]!.GetValue<string>());
    }

    [Fact]
    public async Task Progress_notifications_arrive_before_the_answer()
    {
        using var srv = FakeServer.Start();
        var fx = JsonNode.Parse(File.ReadAllText(Path.Combine(ContractTests.FixturesDir, "install.1.json")))!.AsObject();
        var notes = fx["notifications"]!.AsArray().Select(n => n!.AsObject()).ToList();
        var err = fx["response"]!["error"]!.AsObject();
        srv.On("install", _ => new FakeServer.Reply(null, (JsonObject)err.DeepClone(), notes));
        await using var c = await PaguroClient.ConnectAsync(srv.PipeName);
        var seen = new List<Progress>();
        var ex = await Assert.ThrowsAsync<PaguroException>(() => c.InstallAsync(new InstallParams { Distro = "f", Path = "C:\\f.vhd" }, new Sync<Progress>(seen.Add)));
        Assert.Equal(notes.Count, seen.Count);
        Assert.Equal("host", seen[0].Step);
        Assert.Equal("running", seen[0].State);
        Assert.Contains(seen, p => p.Step == "build" && p.State == "failed");
        Assert.Contains("STUB", ex.Message);
    }

    [Fact]
    public async Task A_missing_secret_is_asked_back()
    {
        using var srv = FakeServer.Start();
        srv.OnError("stage-setup", "refused", 3, "Linux passphrase: not given",
            """{"needs_input":"linux_passphrase","param":"linux_passphrase","prompt":"Linux passphrase","confirm":true}""");
        await using var c = await PaguroClient.ConnectAsync(srv.PipeName);
        var ex = await Assert.ThrowsAsync<PaguroException>(() => c.StageSetupAsync());
        Assert.Equal("refused", ex.Code);
        Assert.Equal(3, ex.Exit);
        Assert.NotNull(ex.NeedsInput);
        Assert.Equal("linux_passphrase", ex.NeedsInput!.Value);
        Assert.True(ex.NeedsInput.Confirm);
    }

    [Fact]
    public async Task Secrets_and_common_parameters_travel_but_unset_ones_do_not()
    {
        using var srv = FakeServer.Start();
        srv.OnData("protection.set", """{"choice":"tpm_pin","keyboard":"de","pin_bypass":true,"pending":[]}""");
        await using var c = await PaguroClient.ConnectAsync(srv.PipeName);
        var r = await c.ProtectionSetAsync(new ProtectionSetParams { Choice = "tpm_pin", Keyboard = "de", Pin = "4711", DryRun = true });
        Assert.Equal("de", r.Data.Keyboard);
        var p = srv.Calls.Single().Params;
        Assert.Equal("4711", p["pin"]!.GetValue<string>());
        Assert.True(p["dry_run"]!.GetValue<bool>());
        Assert.False(p.ContainsKey("linux_passphrase"));
        Assert.False(p.ContainsKey("target"));
    }

    [Fact]
    public async Task Unknown_method_and_several_calls_on_one_connection()
    {
        using var srv = FakeServer.Start();
        srv.OnData("status", """{"elevated":false,"uefi":true,"arch":"x64","future_field":1}""");
        await using var c = await PaguroClient.ConnectAsync(srv.PipeName);
        var s1 = await c.StatusAsync();
        var s2 = await c.StatusAsync();
        Assert.Equal("x64", s2.Data.Arch);
        Assert.True(s1.Data.Extra!.ContainsKey("future_field"));
        var ex = await Assert.ThrowsAsync<PaguroException>(() => c.SecureBootStatusAsync());
        Assert.Equal(-32601, ex.RpcCode);
        Assert.Equal("usage", ex.Code);
    }

    /// <summary>IProgress that reports synchronously (Progress&lt;T&gt; posts).</summary>
    sealed class Sync<T>(Action<T> a) : IProgress<T>
    {
        public void Report(T value) => a(value);
    }
}
