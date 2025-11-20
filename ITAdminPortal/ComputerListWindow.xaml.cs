using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace ITAdminPortal
{
    public partial class ComputerListWindow : Window
    {
        private string defaultListPath;
        private List<string> computers;

        public ComputerListWindow()
        {
            InitializeComponent();
            computers = new List<string>();
            defaultListPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ITAdminPortal", "ComputerList.txt");
            LoadComputerList();
        }

        private void LoadComputerList()
        {
            try
            {
                if (File.Exists(defaultListPath))
                {
                    computers = File.ReadAllLines(defaultListPath)
                        .Where(line => !string.IsNullOrWhiteSpace(line))
                        .Select(line => line.Trim())
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading computer list: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            
            RefreshListBox();
        }

        private void RefreshListBox()
        {
            ComputerListBox.Items.Clear();
            foreach (var computer in computers)
            {
                ComputerListBox.Items.Add(computer);
            }
        }

        private void AddButton_Click(object sender, RoutedEventArgs e)
        {
            string computer = ComputerTextBox.Text.Trim();
            if (!string.IsNullOrWhiteSpace(computer))
            {
                if (!computers.Contains(computer, StringComparer.OrdinalIgnoreCase))
                {
                    computers.Add(computer);
                    RefreshListBox();
                    ComputerTextBox.Clear();
                }
                else
                {
                    MessageBox.Show("Computer already in list.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        private void RemoveButton_Click(object sender, RoutedEventArgs e)
        {
            if (ComputerListBox.SelectedItem != null)
            {
                string selected = ComputerListBox.SelectedItem.ToString();
                computers.Remove(selected);
                RefreshListBox();
            }
            else
            {
                MessageBox.Show("Please select a computer to remove.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ImportButton_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                Title = "Import Computer List"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var imported = File.ReadAllLines(dialog.FileName)
                        .Where(line => !string.IsNullOrWhiteSpace(line))
                        .Select(line => line.Trim())
                        .ToList();

                    foreach (var computer in imported)
                    {
                        if (!computers.Contains(computer, StringComparer.OrdinalIgnoreCase))
                        {
                            computers.Add(computer);
                        }
                    }

                    RefreshListBox();
                    MessageBox.Show($"Imported {imported.Count} computer(s).", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error importing file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.SaveFileDialog dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                Title = "Export Computer List",
                FileName = "ComputerList.txt"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllLines(dialog.FileName, computers);
                    MessageBox.Show($"Exported {computers.Count} computer(s) to {dialog.FileName}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error exporting file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void AddSingleButton_Click(object sender, RoutedEventArgs e)
        {
            AddButton_Click(sender, e);
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string directory = Path.GetDirectoryName(defaultListPath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                File.WriteAllLines(defaultListPath, computers);
                MessageBox.Show($"Saved {computers.Count} computer(s) to list.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                this.DialogResult = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving list: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        public string GetComputerListPath()
        {
            return defaultListPath;
        }
    }
}

