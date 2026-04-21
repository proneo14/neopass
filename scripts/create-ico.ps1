param(
    [string]$OutputPath,
    [string[]]$PngPaths
)

$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)

$count = $PngPaths.Length

# ICO header
$bw.Write([UInt16]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]$count)

Add-Type -AssemblyName System.Drawing

# Read all PNG data
$allData = @()
$allSizes = @()
foreach ($p in $PngPaths) {
    $img = [System.Drawing.Image]::FromFile((Resolve-Path $p).Path)
    $w = $img.Width
    $h = $img.Height
    $img.Dispose()
    $data = [System.IO.File]::ReadAllBytes((Resolve-Path $p).Path)
    $allData += ,$data
    $allSizes += ,@($w, $h)
}

# Calculate data offset
$dataOffset = 6 + (16 * $count)

# Write directory entries
for ($i = 0; $i -lt $count; $i++) {
    $w = $allSizes[$i][0]
    $h = $allSizes[$i][1]
    $bw.Write([byte]$(if ($w -ge 256) { 0 } else { $w }))
    $bw.Write([byte]$(if ($h -ge 256) { 0 } else { $h }))
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]32)
    $bw.Write([UInt32]$allData[$i].Length)
    $bw.Write([UInt32]$dataOffset)
    $dataOffset += $allData[$i].Length
}

# Write PNG data
for ($i = 0; $i -lt $count; $i++) {
    $bw.Write($allData[$i])
}

$bw.Flush()
[System.IO.File]::WriteAllBytes($OutputPath, $ms.ToArray())
$bw.Dispose()
$ms.Dispose()

Write-Host "Created ICO: $OutputPath ($count sizes)"
