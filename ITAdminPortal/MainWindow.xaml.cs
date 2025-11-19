using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace ITAdminPortal
{
    public partial class MainWindow : Window
    {
        private ObservableCollection<ScriptInfo> allScripts;
        private ObservableCollection<ScriptInfo> filteredScripts;
        private bool isHebrew = false;
        private Dictionary<string, Dictionary<string, string>> translations;

        public MainWindow()
        {
            InitializeComponent();
            InitializeTranslations();
            LoadScripts();
            UpdateLanguage();
        }

        private void InitializeTranslations()
        {
            translations = new Dictionary<string, Dictionary<string, string>>
            {
                ["en"] = new Dictionary<string, string>
                {
                    ["Title"] = "Script Gallery",
                    ["Categories"] = "Categories",
                    ["AllScripts"] = "All Scripts",
                    ["Monitoring"] = "Monitoring",
                    ["UserMgmt"] = "User Management",
                    ["ComputerMgmt"] = "Computer Management",
                    ["ADMgmt"] = "Active Directory",
                    ["Security"] = "Security",
                    ["Network"] = "Network",
                    ["Installation"] = "Installation",
                    ["Search"] = "Search scripts...",
                    ["About"] = "About"
                },
                ["he"] = new Dictionary<string, string>
                {
                    ["Title"] = "גלריית סקריפטים",
                    ["Categories"] = "קטגוריות",
                    ["AllScripts"] = "כל הסקריפטים",
                    ["Monitoring"] = "ניטור",
                    ["UserMgmt"] = "ניהול משתמשים",
                    ["ComputerMgmt"] = "ניהול מחשבים",
                    ["ADMgmt"] = "Active Directory",
                    ["Security"] = "אבטחה",
                    ["Network"] = "רשת",
                    ["Installation"] = "התקנות",
                    ["Search"] = "חפש סקריפטים...",
                    ["About"] = "אודות"
                }
            };
        }

        private void LoadScripts()
        {
            allScripts = new ObservableCollection<ScriptInfo>
            {
                new ScriptInfo { Name = "Monitor Computers", FileName = "Monitor-Computers.ps1", 
                    Category = "Monitoring", Description = "Comprehensive monitoring of computers" },
                new ScriptInfo { Name = "Get Installed Apps", FileName = "Get-InstalledApps.ps1", 
                    Category = "Monitoring", Description = "Get all installed applications from remote computers" },
                new ScriptInfo { Name = "Get Computer Time", FileName = "Get-ComputerTime.ps1", 
                    Category = "Monitoring", Description = "Get time and timezone from computers" },
                new ScriptInfo { Name = "Get Battery Status", FileName = "Get-BatteryStatus.ps1", 
                    Category = "Monitoring", Description = "Get battery status from laptops" },
                new ScriptInfo { Name = "Get Disk Space", FileName = "Get-DiskSpace.ps1", 
                    Category = "Monitoring", Description = "Check disk space on remote computers" },
                new ScriptInfo { Name = "Get Network Speed", FileName = "Get-NetworkSpeed.ps1", 
                    Category = "Network", Description = "Get LAN/WiFi speeds from computers" },
                new ScriptInfo { Name = "Get Monitor Info", FileName = "Get-MonitorInfo.ps1", 
                    Category = "Monitoring", Description = "Get monitor brand and information" },
                new ScriptInfo { Name = "Get Computer Devices", FileName = "Get-ComputerDevices.ps1", 
                    Category = "Monitoring", Description = "Get device information from computers" },
                new ScriptInfo { Name = "Get Computer User Status", FileName = "Get-ComputerUserStatus.ps1", 
                    Category = "Monitoring", Description = "Get logged on users count" },
                new ScriptInfo { Name = "Get Secure Boot Status", FileName = "Get-SecureBootStatus.ps1", 
                    Category = "Security", Description = "Query Secure Boot status" },
                new ScriptInfo { Name = "Get LAPS Password", FileName = "Get-LAPSPassword.ps1", 
                    Category = "Security", Description = "Retrieve LAPS passwords" },
                new ScriptInfo { Name = "Get Local Admins", FileName = "Get-LocalAdmins.ps1", 
                    Category = "Security", Description = "Get local administrator accounts" },
                new ScriptInfo { Name = "Get Locked Users", FileName = "Get-LockedUsers.ps1", 
                    Category = "Security", Description = "Find locked user accounts" },
                new ScriptInfo { Name = "Get Share Permissions", FileName = "Get-SharePermissions.ps1", 
                    Category = "Security", Description = "Get shared folder permissions" },
                new ScriptInfo { Name = "Get Users In Groups", FileName = "Get-UsersInGroups.ps1", 
                    Category = "ADMgmt", Description = "Find users in groups and OUs" },
                new ScriptInfo { Name = "Get User Count By Group", FileName = "Get-UserCountByGroup.ps1", 
                    Category = "ADMgmt", Description = "Count users in specific groups" },
                new ScriptInfo { Name = "Get Users With Attributes", FileName = "Get-UsersWithAttributes.ps1", 
                    Category = "ADMgmt", Description = "Get users with specified attributes" },
                new ScriptInfo { Name = "Get Users With Empty Attributes", FileName = "Get-UsersWithEmptyAttributes.ps1", 
                    Category = "ADMgmt", Description = "Find users with empty attributes" },
                new ScriptInfo { Name = "Get Reserved Computers", FileName = "Get-ReservedComputers.ps1", 
                    Category = "ADMgmt", Description = "Find reserved computers" },
                new ScriptInfo { Name = "Get AD Object Tree", FileName = "Get-ADObjectTree.ps1", 
                    Category = "ADMgmt", Description = "Build tree of AD objects" },
                new ScriptInfo { Name = "Get Organization Tree", FileName = "Get-OrganizationTree.ps1", 
                    Category = "ADMgmt", Description = "Create organization tree by attributes" },
                new ScriptInfo { Name = "Get Groups By Prefix", FileName = "Get-GroupsByPrefix.ps1", 
                    Category = "ADMgmt", Description = "Get groups starting with prefix" },
                new ScriptInfo { Name = "Set User Password", FileName = "Set-UserPassword.ps1", 
                    Category = "UserMgmt", Description = "Generate and set passwords for users" },
                new ScriptInfo { Name = "Set User Disable Move", FileName = "Set-UserDisableMove.ps1", 
                    Category = "UserMgmt", Description = "Disable users and move to OU" },
                new ScriptInfo { Name = "Set Group Membership", FileName = "Set-GroupMembership.ps1", 
                    Category = "UserMgmt", Description = "Add/remove users from groups" },
                new ScriptInfo { Name = "New AD User/Group", FileName = "New-ADUserGroup.ps1", 
                    Category = "UserMgmt", Description = "Create users or groups" },
                new ScriptInfo { Name = "Invoke User Logoff", FileName = "Invoke-UserLogoff.ps1", 
                    Category = "UserMgmt", Description = "Logout specific user from computers" },
                new ScriptInfo { Name = "Invoke Idle User Logoff", FileName = "Invoke-IdleUserLogoff.ps1", 
                    Category = "UserMgmt", Description = "Logoff idle users" },
                new ScriptInfo { Name = "Install Software Remote", FileName = "Install-SoftwareRemote.ps1", 
                    Category = "Installation", Description = "Install software on remote computers" },
                new ScriptInfo { Name = "New Desktop Shortcut", FileName = "New-DesktopShortcut.ps1", 
                    Category = "UserMgmt", Description = "Create desktop shortcuts for users" },
                new ScriptInfo { Name = "Set Domain Join", FileName = "Set-DomainJoin.ps1", 
                    Category = "ComputerMgmt", Description = "Join/leave domain" },
                new ScriptInfo { Name = "Restart Computer List", FileName = "Restart-ComputerList.ps1", 
                    Category = "ComputerMgmt", Description = "Restart list of computers" },
                new ScriptInfo { Name = "Stop Computer List", FileName = "Stop-ComputerList.ps1", 
                    Category = "ComputerMgmt", Description = "Shutdown list of computers" },
                new ScriptInfo { Name = "Stop Process Remote", FileName = "Stop-ProcessRemote.ps1", 
                    Category = "ComputerMgmt", Description = "Kill processes on remote computers" },
                new ScriptInfo { Name = "Set Remote Registry", FileName = "Set-RemoteRegistry.ps1", 
                    Category = "ComputerMgmt", Description = "Change remote registry values" },
                new ScriptInfo { Name = "New Local Admin", FileName = "New-LocalAdmin.ps1", 
                    Category = "Security", Description = "Create local admin accounts" },
                new ScriptInfo { Name = "Clear Computer Cache", FileName = "Clear-ComputerCache.ps1", 
                    Category = "ComputerMgmt", Description = "Clear cache on computers" },
                new ScriptInfo { Name = "Clear Recycle Bin Remote", FileName = "Clear-RecycleBinRemote.ps1", 
                    Category = "ComputerMgmt", Description = "Clear recycle bin remotely" },
                new ScriptInfo { Name = "Search File Remote", FileName = "Search-FileRemote.ps1", 
                    Category = "ComputerMgmt", Description = "Search for files/folders remotely" },
                new ScriptInfo { Name = "Find Locked Files", FileName = "Find-LockedFiles.ps1", 
                    Category = "ComputerMgmt", Description = "Find locked files on servers" }
            };

            filteredScripts = new ObservableCollection<ScriptInfo>(allScripts);
            ScriptsList.ItemsSource = filteredScripts;
        }

        private void UpdateLanguage()
        {
            string lang = isHebrew ? "he" : "en";
            TitleText.Text = translations[lang]["Title"];
            AllScriptsBtn.Content = translations[lang]["AllScripts"];
            MonitoringBtn.Content = translations[lang]["Monitoring"];
            UserMgmtBtn.Content = translations[lang]["UserMgmt"];
            ComputerMgmtBtn.Content = translations[lang]["ComputerMgmt"];
            ADMgmtBtn.Content = translations[lang]["ADMgmt"];
            SecurityBtn.Content = translations[lang]["Security"];
            NetworkBtn.Content = translations[lang]["Network"];
            InstallationBtn.Content = translations[lang]["Installation"];
            SearchBox.Text = translations[lang]["Search"];
            AboutButton.Content = translations[lang]["About"];
        }

        private void LangButton_Click(object sender, RoutedEventArgs e)
        {
            isHebrew = !isHebrew;
            UpdateLanguage();
        }

        private void CategoryButton_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            string category = btn.Tag.ToString();
            
            if (category == "All")
            {
                filteredScripts.Clear();
                foreach (var script in allScripts)
                    filteredScripts.Add(script);
            }
            else
            {
                filteredScripts.Clear();
                foreach (var script in allScripts.Where(s => s.Category == category))
                    filteredScripts.Add(script);
            }
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string search = SearchBox.Text.ToLower();
            if (string.IsNullOrWhiteSpace(search) || search == translations[isHebrew ? "he" : "en"]["Search"].ToLower())
            {
                filteredScripts.Clear();
                foreach (var script in allScripts)
                    filteredScripts.Add(script);
                return;
            }

            filteredScripts.Clear();
            foreach (var script in allScripts.Where(s => 
                s.Name.ToLower().Contains(search) || 
                s.Description.ToLower().Contains(search) ||
                s.Category.ToLower().Contains(search)))
            {
                filteredScripts.Add(script);
            }
        }

        private void ScriptCard_MouseEnter(object sender, MouseEventArgs e)
        {
            Border border = sender as Border;
            border.Background = new SolidColorBrush(Color.FromRgb(15, 33, 62));
            border.BorderBrush = new SolidColorBrush(Color.FromRgb(0, 217, 255));
        }

        private void ScriptCard_MouseLeave(object sender, MouseEventArgs e)
        {
            Border border = sender as Border;
            border.Background = new SolidColorBrush(Color.FromRgb(15, 15, 35));
            border.BorderBrush = new SolidColorBrush(Color.FromRgb(0, 255, 65));
        }

        private void ScriptCard_Click(object sender, MouseButtonEventArgs e)
        {
            Border border = sender as Border;
            ScriptInfo script = border.DataContext as ScriptInfo;
            
            if (script != null)
            {
                ScriptRunnerWindow runner = new ScriptRunnerWindow(script, isHebrew);
                runner.ShowDialog();
            }
        }

        private void AboutButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(
                "IT Admin Portal v1.0\n\n" +
                "Cyber Style Script Gallery\n" +
                "Comprehensive PowerShell Script Collection\n\n" +
                "Features:\n" +
                "- 40+ IT Administration Scripts\n" +
                "- Active Directory Management\n" +
                "- Computer Monitoring\n" +
                "- User Management\n" +
                "- Security Tools\n" +
                "- Network Tools\n\n" +
                "Hebrew/English Support",
                "About IT Admin Portal",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }

    public class ScriptInfo
    {
        public string Name { get; set; }
        public string FileName { get; set; }
        public string Category { get; set; }
        public string Description { get; set; }
    }
}

