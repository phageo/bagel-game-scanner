// Bagel.exe - the start program of the Bagel package (0.9-beta final polish, phageo 2026-10-25).
//
// Built by tools/build_launcher.py with the .NET Framework's own csc.exe (dev-only, like the C#
// test fixtures); its version and name come from a second file the builder writes
// (models.TOOL_VERSION). It does one thing: start the package's own Python without a console,
//
//     "<this folder>\python\pythonw.exe" -I "<this folder>\app\GameSafetyScanner.pyw" <its arguments>
//
// wait for it, and exit with its exit code. Its arguments are passed on exactly as written (the
// right-click menu gives "%1" or --launch "%1"). It reads nothing else and changes nothing.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

static class Bagel
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int MessageBoxW(IntPtr owner, string text, string caption, uint type);

    // The command line without this program's own name (the first part, quoted or not),
    // as Windows wrote it - so every argument reaches Python unchanged.
    static string Arguments(string line)
    {
        int i = 0;
        while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
        if (i < line.Length && line[i] == '"')
        {
            i++;
            while (i < line.Length && line[i] != '"') i++;
            if (i < line.Length) i++;
        }
        while (i < line.Length && !char.IsWhiteSpace(line[i])) i++;
        while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
        return line.Substring(i);
    }

    [STAThread]
    static int Main()
    {
        string top = AppDomain.CurrentDomain.BaseDirectory;
        string python = Path.Combine(Path.Combine(top, "python"), "pythonw.exe");
        string app = Path.Combine(Path.Combine(top, "app"), "GameSafetyScanner.pyw");
        if (!File.Exists(python) || !File.Exists(app))
        {
            MessageBoxW(IntPtr.Zero, "Bagel could not start: a file of the package is missing.\n\n"
                        + python + "\n" + app + "\n\nDownload Bagel again.", "Bagel", 0x10);
            return 1;
        }
        string rest = Arguments(Environment.CommandLine);
        ProcessStartInfo start = new ProcessStartInfo(python, "-I \"" + app + "\"" + (rest.Length > 0 ? " " + rest : ""));
        start.UseShellExecute = false;
        try
        {
            using (Process child = Process.Start(start))
            {
                child.WaitForExit();
                return child.ExitCode;
            }
        }
        catch (Exception error)
        {
            MessageBoxW(IntPtr.Zero, "Bagel could not start:\n\n" + error.Message, "Bagel", 0x10);
            return 1;
        }
    }
}
