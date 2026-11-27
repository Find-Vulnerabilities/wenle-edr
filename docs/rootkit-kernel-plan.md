# Rootkit 核心層：剩下三項的設計與 VM 驗證計畫

`hidden process` 已在服務端完成（使用者模式 cross-view，實測 1577 次程序啟動、0 誤報）。
以下三項必須改核心驅動，且必須在 VM 驗證後才能上主機；在主機載入未驗證的磁碟過濾
或記憶體掃描程式，最壞情況是無法開機或 bugcheck。

## 1. PsLoadedModuleList cross-view（隱藏驅動）

### 原理
`NtQuerySystemInformation(SystemModuleInformation)` 走 `PsLoadedModuleList`。
DKOM rootkit 把自己從串列摘除後，這條路徑看不到它，但映像仍在核心記憶體。

### 實作
新核心工作項（system thread，每 10 分鐘）：

1. 用 `ZwQuerySystemInformation(SystemModuleInformation)` 取得清單。
2. 用 `MmCopyMemory(MM_COPY_MEMORY_VIRTUAL)` 掃描核心 VA 窗口：
   - 起點：`0xFFFFF800_00000000`
   - 終點：`0xFFFFF900_00000000`
   - 步進：4 KiB
   - 每次讀 64 bytes，找 `MZ` + `PE\0\0` + machine x64 + 合理 `SizeOfImage`
3. 對每個候選基底：
   - 若不在清單 → `hidden-image`（critical）
   - 若在清單但路徑的檔案不存在 → `unlinked-image`（critical）
4. 只做偵測，不卸載（卸載未要求卸載的驅動會 bugcheck）。

### 風險與界線
- 全窗口掃描是 512K 次 `MmCopyMemory`；必須在 VM 量測耗時與對系統的影響。
- 若 rootkit 同時 patch `ZwQuerySystemInformation`，清單本身不可信；需再與
  `PspCidTable`/driver object 交叉比對，這是下一層。
- 候選驗證要嚴格，否則壓縮資料/PE 殘留會誤報。

### VM 驗證
1. 正常 VM：跑 30 分鐘，0 finding。
2. 測試驅動（自行編譯、未簽章）以正常方式載入 → 應為 `unsigned-driver`。
3. 測試驅動在 DriverEntry 把自己從 `PsLoadedModuleList` 摘除 → 應為 `hidden-image`。
4. 觀察 CPU/延遲：掃描期間 system 執行緒 CPU 占比、對檔案 I/O 的影響。

## 2. SSDT / inline hook 掃描

### 原理
- SSDT（`KiServiceTable`）：syscall 編號 → 核心函式位址。
- inline hook：改寫 `Nt*` 函式開頭（`E9 rel32`、`FF 25`、`mov rax; jmp rax`）。

### 實作（先在 VM 做 inline hook，SSDT 次之）
inline hook：

1. 用 `MmGetSystemRoutineAddress` 取得一組關鍵 `Nt*` 位址：
   `NtQuerySystemInformation`、`NtQueryDirectoryFile`、`NtOpenProcess`、
   `NtReadFile`、`NtCreateKey`、`NtQueryValueKey`。
2. 讀前 16 bytes，判定是否為 hook 形狀：
   - `E9 xx xx xx xx`（直接 jmp）
   - `FF 25 xx xx xx xx`（間接 jmp）
   - `48 B8 ... FF E0`（mov rax, imm64; jmp rax）
3. 若命中 → `inline-hook`（critical），記錄函式名與目標位址。

SSDT：

1. 從 `KiSystemCall64`（`IA32_LSTAR` MSR）反組譯找 `KiServiceTable` 的
   `lea`/`mov` 位移。
2. 逐項檢查位址是否落在 `ntoskrnl` 的 `.text` 範圍。
3. 不在範圍 → `ssdt-hook`（critical）。

### 風險與界線
- PatchGuard 會修復/藍屏；本產品只讀不寫，不觸發 KPP。
- SSDT 位址解析依 Windows build 而異，必須版本化並在 VM 用多個 build 驗證。
- 合法 hotpatch/KPP 變更可能造成誤報；先只認 `E9`/`FF 25` 這兩種明確 hook 形狀。

### VM 驗證
1. 正常 VM：0 finding（跑 30 分鐘）。
2. 測試驅動 inline hook `NtQuerySystemInformation` → 應為 `inline-hook`。
3. 測試驅動改 SSDT 一項 → 應為 `ssdt-hook`，且系統不藍屏（測試驅動自行承擔 KPP）。
4. 關閉驅動後 PatchGuard 行為觀察。

## 3. 原始磁碟寫入攔截（磁碟過濾驅動）

### 原理
`\\.\PhysicalDrive0` 的寫入走 disk class driver，不經檔案系統，minifilter 看不到。
需建立 filter device 並 `IoAttachDeviceToDeviceStack` 到 `\Device\Harddisk0\DR0`。

### 實作
1. `IoCreateDevice(..., FILE_DEVICE_DISK, FILE_DEVICE_DISK_FILTER, ...)`。
2. `IoGetDeviceObjectPointer(L"\\Device\\Harddisk0\\DR0", FILE_READ_ATTRIBUTES, ...)`
   取得 disk PDO。
3. attach 後，在 `DriverObject->MajorFunction[IRP_MJ_WRITE]` 檢查：
   - `IoGetCurrentIrpStackLocation(Irp)->Parameters.Write.Length`
   - `...Parameters.Write.ByteOffset`
   - 若 `ByteOffset` 與 `[0, 1 MiB)` 重疊（MBR/VBR/開機區）
     → `Irp->IoStatus.Status = STATUS_ACCESS_DENIED`，完成 IRP，記錄事件。
4. 其他位移照常 `IoSkipCurrentIrpStackLocation` + `IofCallDriver` 往下送。
5. 用 `IoRegisterPlugPlayNotification(GUID_DEVINTERFACE_DISK)` 對其他磁碟動態 attach。
6. 卸載時 `IoDetachDevice` + `IoDeleteDevice`。

### 風險與界線
- 會擋掉合法工具（diskpart、bcdboot、開機修復）；需要允許清單或服務詢問，
  第一版先在 VM 用「只記錄不阻擋」模式驗證，再切換阻擋。
- 掛錯 device stack / 完成 IRP 方式錯誤 → 藍屏或資料損毀；必須 VM。
- BitLocker/儲存空間/RAID 的裝置路徑不同，需逐一驗證。

### VM 驗證
1. 正常 VM：開機、磁碟工具、Windows Update 一輪，0 誤擋、0 bugcheck。
2. 測試程式寫 `\\.\PhysicalDrive0` offset 0 → 被拒（STATUS_ACCESS_DENIED），事件記錄。
3. 測試程式寫 offset 1 MiB 之後 → 允許。
4. 測試 diskpart clean / bcdboot → 預期被擋（記錄），確認可加白名單。
5. 卸載驅動後再測一次，確認 detach 乾淨。

## 共通回報管線

三項偵測都需要把結果送到服務。現有 `FltSendMessage` 事件佇列可重用，但要新增
`EventAction::KernelAnomaly`（wire code、`av-ipc` 對應、服務端 log/通知）。
或者以新的 port 查詢訊息由服務主動拉取；事件推送較符合現有架構。

## 順序建議

1. inline hook 掃描（最小、風險最低）
2. PsLoadedModuleList cross-view（記憶體掃描，需量測成本）
3. 磁碟過濾（風險最高，最後做，且先記錄模式）
4. 三項都在 VM 通過後才進主機
