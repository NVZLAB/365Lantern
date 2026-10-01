using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Lantern.Core;
using Microsoft.Win32;

namespace Lantern.Desktop;

public partial class MainWindow
{
    private void ActionPromptChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ActionPromptDescription is not null) ActionPromptDescription.Text = (ActionPromptPicker.SelectedItem as ActionPrompt)?.Guidance ?? "";
    }
    private void AddActionPrompt(object sender, RoutedEventArgs e)
    {
        if (investigation is null || ActionPromptPicker.SelectedItem is not ActionPrompt prompt) return;
        if (ReportNextSteps.Text.Contains(prompt.Draft, StringComparison.Ordinal)) { StatusLabel.Text = "This suggestion is already in the plan. Edit its owner, scope and verification details."; return; }
        if (ReportNextSteps.Text.Length + prompt.Draft.Length + 2 > ReportNextSteps.MaxLength) { StatusLabel.Text = "Next steps field is full. Edit existing text before adding another action."; return; }
        ReportNextSteps.Text += (ReportNextSteps.Text.Length > 0 ? "\n\n" : "") + prompt.Draft;
        ReportNextSteps.Focus(); ReportNextSteps.CaretIndex = ReportNextSteps.Text.Length;
        StatusLabel.Text = "Suggested action added. Assign an owner and date, edit the scope, and update status only after verification. No tenant changes made.";
    }
    private bool loadingReport;
    private ReportIndicator? editingIndicator;
    private bool AssessmentDirty => editingIndicator is { } row &&
        (AssessmentNotes.Text != (row.Assessment?.Notes ?? "") || (AssessmentStatus.SelectedItem as string ?? "Unexplained") != (row.Assessment?.Status ?? "Unexplained"));
    private bool LeaveAssessment()
    {
        if (!AssessmentDirty) return true;
        var choice = MessageBox.Show(this, "Save your pending indicator assessment before continuing? Choose No to discard these edits. Saved assessments and report text remain in the current session until exported.", "Unsaved assessment", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        if (choice == MessageBoxResult.Cancel) return false;
        if (choice == MessageBoxResult.Yes) return StoreAssessment();
        loadingReport = true;
        AssessmentNotes.Text = editingIndicator?.Assessment?.Notes ?? "";
        AssessmentStatus.SelectedItem = editingIndicator?.Assessment?.Status ?? "Unexplained";
        loadingReport = false;
        return true;
    }
    private void RefreshReport()
    {
        loadingReport = true;
        try
        {
            editingIndicator = null;
            ReportEditor.IsEnabled = investigation is not null && operation is null;
            ReportAvailability.Text = investigation is null ? "Run or import an investigation to prepare a report." :
                "Analyst working report · Notes stay in memory until you export. Starting a new investigation, clearing the session or exiting discards them. Related searches retain reviews for unchanged evidence.";
            var draft = investigation?.Report ?? new ReportDraft();
            ReportCase.Text = draft.CaseReference; ReportAnalyst.Text = draft.Analyst;
            ReportSummary.Text = draft.Summary; ReportImpact.Text = draft.PotentialImpact; ReportAffected.Text = draft.AffectedAccounts;
            ReportNextSteps.Text = draft.NextSteps;
            ActionPromptPicker.ItemsSource = ActionPrompts.All;
            ActionPromptPicker.SelectedIndex = 0;
            AssessmentStatus.ItemsSource = IncidentReport.Statuses;
            ReportIndicators.ItemsSource = investigation is null ? null : IncidentReport.Indicators(investigation);
            ReportIndicators.SelectedIndex = -1;
            AssessmentNotes.Clear(); AssessmentEvidence.Clear(); AssessmentStatus.SelectedIndex = 0;
            AssessmentEditor.IsEnabled = false;
            ReportCounts.Text = investigation is null ? "" : $"{suspicious.Count} automated indicators · {IncidentReport.Indicators(investigation).Count(i => i.Assessment is not null)} assessed. Review coverage in Findings before drawing conclusions.";
        }
        finally { loadingReport = false; }
    }
    private void ReportTextChanged(object sender, TextChangedEventArgs e)
    {
        if (loadingReport || investigation is null || ReportNextSteps is null) return;
        investigation = investigation with { Report = investigation.Report with { CaseReference = ReportCase.Text,
            Analyst = ReportAnalyst.Text, Summary = ReportSummary.Text, PotentialImpact = ReportImpact.Text, AffectedAccounts = ReportAffected.Text, NextSteps = ReportNextSteps.Text } };
    }
    private void ReportIndicatorSelected(object sender, SelectionChangedEventArgs e)
    {
        if (loadingReport) return;
        if (!LeaveAssessment())
        {
            loadingReport = true; ReportIndicators.SelectedItem = editingIndicator; loadingReport = false;
            return;
        }
        AssessmentEditor.IsEnabled = ReportIndicators.SelectedItem is ReportIndicator;
        if (ReportIndicators.SelectedItem is not ReportIndicator row || investigation is null) return;
        editingIndicator = row;
        AssessmentStatus.SelectedItem = row.Assessment?.Status ?? "Unexplained";
        AssessmentNotes.Text = row.Assessment?.Notes ?? "";
        AssessmentEvidence.Text = row.Indicator.Explanation + "\n\n" + JsonSerializer.Serialize(
            investigation.Evidence.Where(item => row.Indicator.EvidenceIds.Contains(item.Id)), new JsonSerializerOptions { WriteIndented = true });
    }
    private void SaveAssessment(object sender, RoutedEventArgs e)
        => StoreAssessment();
    private bool StoreAssessment()
    {
        if (investigation is null || editingIndicator is not ReportIndicator row) return false;
        try
        {
            investigation = IncidentReport.Assess(investigation, row.Indicator, AssessmentStatus.SelectedItem as string ?? "", AssessmentNotes.Text, ReportAnalyst.Text, DateTimeOffset.UtcNow);
            var selectedKey = (ReportIndicators.SelectedItem as ReportIndicator)?.Key;
            var updated = IncidentReport.Indicators(investigation);
            loadingReport = true;
            ReportIndicators.ItemsSource = updated;
            editingIndicator = updated.First(i => i.Key == row.Key);
            AssessmentNotes.Text = editingIndicator.Assessment!.Notes;
            ReportIndicators.SelectedItem = updated.FirstOrDefault(i => i.Key == selectedKey);
            loadingReport = false;
            ReportCounts.Text = $"{updated.Count} automated indicators · {updated.Count(i => i.Assessment is not null)} assessed. Review coverage in Findings before drawing conclusions.";
            StatusLabel.Text = "Assessment saved in this session. Export to retain the report and notes.";
            return true;
        }
        catch (ArgumentException ex) { StatusLabel.Text = ex.Message; return false; }
    }
    private void ExportReportHtml(object sender, RoutedEventArgs e)
    {
        if (investigation is null) return;
        if (!LeaveAssessment()) return;
        var dialog = new SaveFileDialog { Title = "Save incident report", Filter = "HTML report (*.html)|*.html", FileName = $"365Lantern-report-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.html", OverwritePrompt = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, IncidentReport.Html(investigation), new UTF8Encoding(false));
            StatusLabel.Text = "Report saved. Open the HTML file locally and use Print → Save as PDF. Export the full archive to retain JSON/CSV evidence and integrity hashes.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { StatusLabel.Text = "Report export failed. Check the destination; a partial file may exist."; }
    }
}
