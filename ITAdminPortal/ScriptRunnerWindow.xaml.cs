using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;

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
                // Try multiple paths to find the script
                string[] possiblePaths = {
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, script.FileName),
                    Path.Combine(Directory.GetCurrentDirectory(), script.FileName),
                    Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "..", "..", "..", "..", script.FileName),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "reports-it-admin", script.FileName),
                    script.FileName  // Try direct path
                };
                
                string scriptPath = null;
                foreach (string path in possiblePaths)
                {
                    if (File.Exists(path))
                    {
                        scriptPath = path;
                        break;
                    }
                }
                
                if (scriptPath == null)
                {
                    OutputBox.Text += $"\n\nERROR: Script file not found.\n";
                    OutputBox.Text += $"Searched in:\n";
                    foreach (string path in possiblePaths)
                    {
                        OutputBox.Text += $"  - {path}\n";
                    }
                    OutputBox.Text += $"\nPlease ensure the script file '{script.FileName}' is in the same directory as this application or update the path.";
                    return;
                }

                OutputBox.Text += $"\n\nExecuting: {script.FileName}...\n";
                OutputBox.Text += $"Script Path: {scriptPath}\n";
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

