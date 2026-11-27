# Wait for the two-hour benign collection, then train and measure without help.
#
# The chain is the one the last rounds proved: wait for the collection to say it
# is done, freeze the log with a copy of the technique labels from the verified
# run, train on technique stories plus the new benign stories, and report both
# numbers the objective asks for -- false positives on benign work the model has
# not seen, and recall on techniques it has not seen. Everything goes to
# target\final-report.txt so the result survives the console.

$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\wensz\Downloads\wenle-av'
$marker = Join-Path $repo 'target\benign-2h.log'
$report = Join-Path $repo 'target\final-report.txt'

"waiting for the benign collection" | Set-Content $report -Encoding ASCII
while ((Select-String -Path $marker -Pattern 'benign 2h done' -ErrorAction SilentlyContinue) -eq $null) {
    Start-Sleep -Seconds 60
}

$run = Join-Path $repo 'target\runs\benign-2h'
New-Item -ItemType Directory -Path $run -Force | Out-Null
Copy-Item 'C:\ProgramData\WenleAV\logs\behaviour.log' (Join-Path $run 'benign.log') -Force
"frozen benign log: $((Get-Item (Join-Path $run 'benign.log')).Length) bytes" | Add-Content $report

& python (Join-Path $repo 'tools\benign_corpus.py') --log (Join-Path $run 'benign.log') --out (Join-Path $repo 'target\benign-2h.npz') 2>&1 | Add-Content $report
& python (Join-Path $repo 'tools\train_final.py') --techniques (Join-Path $repo 'target\corpus-check.npz') --benign (Join-Path $repo 'target\benign-2h.npz') --out (Join-Path $repo 'target\model-final2.bin') 2>&1 | Add-Content $report
"done" | Add-Content $report
