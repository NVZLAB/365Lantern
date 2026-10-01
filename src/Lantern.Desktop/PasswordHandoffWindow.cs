using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using System.Windows.Controls;

namespace Lantern.Desktop;

// Ephemeral handoff only; never part of the case or exported evidence.
public sealed class PasswordHandoffWindow : Window
{
    public PasswordHandoffWindow(SecureString password, string account, string outcome)
    {
        Title = "Temporary password handoff — 365Lantern";
        FontFamily = new System.Windows.Media.FontFamily("Segoe UI"); FontSize = 14;
        Width = 620; SizeToContent = SizeToContent.Height; ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; ShowInTaskbar = false;
        SetResourceReference(BackgroundProperty, "PageBrush");
        var panel = new StackPanel { Margin = new Thickness(24) };
        Content = panel;
        panel.Children.Add(new TextBlock { Text = account + "\n\n" + (outcome == "Accepted" ? "Microsoft accepted the reset." : "The reset outcome is unknown. This password may have taken effect; verify with Microsoft before another attempt.") + "\n\nDeliver through your approved secure channel. This window is the last opportunity to retrieve the password. It is excluded from reports and discarded from this window when closed. If you copy it, your clipboard and clipboard history are outside Lantern's control.", TextWrapping = TextWrapping.Wrap });
        var reveal = new CheckBox { Content = "Reveal temporary password", Margin = new Thickness(0,16,0,8) };
        reveal.SetResourceReference(ForegroundProperty, "InkBrush");
        var secret = new TextBox { IsReadOnly = true, Visibility = Visibility.Collapsed, Margin = new Thickness(0,0,0,16) };
        reveal.Checked += (_, _) =>
        {
            var pointer = Marshal.SecureStringToBSTR(password);
            try { secret.Text = Marshal.PtrToStringBSTR(pointer); secret.Visibility = Visibility.Visible; }
            finally { Marshal.ZeroFreeBSTR(pointer); }
        };
        reveal.Unchecked += (_, _) => { secret.Clear(); secret.Visibility = Visibility.Collapsed; };
        var close = new Button { Content = "Done — discard password", HorizontalAlignment = HorizontalAlignment.Right };
        close.Click += (_, _) => Close();
        panel.Children.Add(reveal); panel.Children.Add(secret); panel.Children.Add(close);
        Closed += (_, _) => secret.Clear();
    }
}
