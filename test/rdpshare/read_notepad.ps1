Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Window)
$wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)
foreach ($w in $wins) {
    $name = $w.Current.Name
    if ($name -like "*Notepad*") {
        Write-Output "WINDOW: $name (pid=$($w.Current.ProcessId))"
        $docCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Document)
        $doc = $w.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $docCond)
        if ($doc -ne $null) {
            $pattern = $doc.GetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern)
            $text = $pattern.DocumentRange.GetText(-1)
            Write-Output "TEXT=[$text]"
        } else {
            Write-Output "no document element found"
        }
    }
}
