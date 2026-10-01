# Rebuild the ICO from the same vector geometry used by the desktop lantern.
# Run with Windows PowerShell -STA; transparent PNG frames are embedded in the ICO.
param([string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Lantern.Desktop/Assets/Lantern.ico'))
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore,WindowsBase
$outline = [Windows.Media.Geometry]::Parse('M 14,15 L 14,8 Q 14,3 20,3 L 28,3 Q 34,3 34,8 L 34,15 M 12,20 L 36,20 L 42,51 Q 43,58 36,59 L 12,59 Q 5,58 6,51 Z')
$flame = [Windows.Media.Geometry]::Parse('M24,28 L33,43 L24,53 L15,43 Z')
$brush = [Windows.Media.SolidColorBrush]::new([Windows.Media.ColorConverter]::ConvertFromString('#45ACFF'))
$pen = [Windows.Media.Pen]::new($brush,6)
$pen.LineJoin = 'Round'
$pen.StartLineCap = $pen.EndLineCap = 'Round'
$sizes = @(16,20,24,32,40,48,64,96,128,256)
$frames = @()
foreach ($size in $sizes) {
    $visual = [Windows.Media.DrawingVisual]::new()
    $context = $visual.RenderOpen()
    $scale = $size / 68.0
    $context.PushTransform([Windows.Media.TranslateTransform]::new(($size - 48 * $scale)/2,3 * $scale))
    $context.PushTransform([Windows.Media.ScaleTransform]::new($scale,$scale))
    $context.DrawGeometry($null,$pen,$outline)
    $context.DrawGeometry($brush,$null,$flame)
    $context.Close()
    $bitmap = [Windows.Media.Imaging.RenderTargetBitmap]::new($size,$size,96,96,[Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder = [Windows.Media.Imaging.PngBitmapEncoder]::new()
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $buffer = [IO.MemoryStream]::new()
    $encoder.Save($buffer)
    $frames += ,$buffer.ToArray()
    $buffer.Dispose()
}
$stream = [IO.File]::Create($OutputPath)
$writer = [IO.BinaryWriter]::new($stream)
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i=0; $i -lt $sizes.Count; $i++) {
        $dimension = if ($sizes[$i] -eq 256) { 0 } else { $sizes[$i] }
        $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
        $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$frames[$i].Length); $writer.Write([uint32]$offset)
        $offset += $frames[$i].Length
    }
    foreach ($frame in $frames) { $writer.Write([byte[]]$frame) }
} finally { $writer.Dispose(); $stream.Dispose() }
Write-Output "Generated transparent multi-resolution icon: $OutputPath"
