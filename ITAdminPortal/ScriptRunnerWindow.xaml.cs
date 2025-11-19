using System;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Windows;

namespace ITAdminPortal
{
    public partial class ScriptRunnerWindow : Window
    {
        private ScriptInfo script;
        private bool isHebrew;

        public ScriptRunnerWindow(ScriptInfo scriptInfo, bool isHebrewLang)
        {
            InitializeComponent();
            script = scriptInfo;
            isHebrew = isHebrewLang;
            ScriptTitle.Text = script.Name;
            OutputBox.Text = $"Script: {script.FileName}\nCategory: {script.Category}\n\n{script.Description}\n\nReady to run...";
        }

        private void RunButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string scriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", script.FileName);
                
                if (!File.Exists(scriptPath))
                {
                    OutputBox.Text += $"\n\nERROR: Script file not found at: {scriptPath}";
                    return;
                }

                OutputBox.Text += $"\n\nExecuting: {script.FileName}...\n";
                OutputBox.Text += "=" + new string('=', 50) + "\n\n";

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -File \"{scriptPath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    OutputBox.Text += output;
                    if (!string.IsNullOrEmpty(error))
                    {
                        OutputBox.Text += $"\n\nERRORS:\n{error}";
                    }
                    OutputBox.Text += $"\n\nExit Code: {process.ExitCode}";
                }
            }
            catch (Exception ex)
            {
                OutputBox.Text += $"\n\nEXCEPTION: {ex.Message}\n{ex.StackTrace}";
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}

