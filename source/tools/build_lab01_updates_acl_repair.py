"""New, fixed updates-root repair derived from the preserved root-repair BAT."""
from pathlib import Path
import hashlib
import json
import zipfile
from tools.build_lab01_acl_repair import DID,render as root_render

ROOT=Path(__file__).resolve().parents[1]
SID='S-1-5-21-111111111-222222222-333333333-11016'


def render(fixture=None):
    # Refuse accidental reuse of a future, behaviorally different base generator.
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-LAB01-Data-ACL-Repair-20261029.zip') as z:
        assert root_render()==z.read('Repair-LAB01-Data-ACL.bat')
    cfg=dict(parent=rf'C:\ProgramData\GuardDeskPilot\USBControl\{DID}',trustee='*'+SID)
    if fixture:cfg.update(fixture)
    text=root_render(cfg).decode('utf-8')
    def replace(old,new,count):
        nonlocal text
        assert text.count(old)==count,(old,text.count(old),count)
        text=text.replace(old,new)
    replace('set "GD_ROOT=%GD_PARENT%\\%GD_DID%"','set "GD_ROOT=%GD_PARENT%\\updates"',1)
    replace('"%GD_DID%" /save','"updates" /save',2)
    replace('LAB01-ACL-','LAB01-Updates-ACL-',5)
    replace('scoped root DACL repair','scoped updates DACL repair',1)
    replace('scoped data ACL repair','scoped updates ACL repair',1)
    replace(r'echo 3. EXAMPLE\user1 is the extra explicit root allow grant reported; no child reparse links.',
            'echo 3. This exact SID is the extra explicit updates grant; its ten reported children inherit it. No child reparse links.',1)
    replace('echo This changes ONLY the named allow grant on the root directory above.',
            'echo This changes ONLY the named allow grant on the updates directory above.',1)
    return text.encode('utf-8')


README='''LAB01 updates 額外授權修復（未簽章內部維護工具）
依這次Audit完整2246物件／118目錄：只找到updates本身一筆明確user1全權授權，以及10個繼承項。
上一層端點資料根已修好；現用Updater／USBControl的DACL未觀察到其他不受信任寫入。
固定目標：C:\\ProgramData\\GuardDeskPilot\\USBControl\\ee1e1e17c6c8730a37603b1e\\updates
固定移除SID：S-1-5-21-111111111-222222222-333333333-11016（報告中的EXAMPLE\\user1）。

LAB01解壓至MIS私人資料夾，右鍵Repair-LAB01-Updates-ACL.bat以系統管理員執行。
選R，核對畫面固定目標／SID與五項維護條件後選Y。C只是可選的單一目標唯讀查詢，不必先C。
R先存updates自身DACL及SHA256，再單次remove:g固定SID /l；Windows向繼承項傳播。
沒有/T／reset／owner更改，不逐檔移除授權；不讀或修改設定／交易內容，不刪檔或改身分／佇列。
不停止或啟動排程、不執行更新。唯一Agent呼叫為既有Updater的唯讀updater-check。
備份只含updates根DACL，不含owner／SACL或獨立子項；保留之前完整Audit和所有備份。
恢復根DACL亦可能傳播並恢復不安全授權，僅MIS核對備份hash及無新工作後手動決定，不自動還原。
管理員icacls還原在公司現場未驗收；之前非管理員測試曾回1300，不以權利列存在當成還原成功。

成功應顯示INSTALLED_CHECK_PASSED_CAPACITY_ARCHIVE_STILL_PENDING；提供LAB01-Updates-ACL-Repair-*.txt。
若仍失敗，保留原CLI錯誤及本次Before／After／Hash，停止，不重跑大掃描或擴大修權限。
即使檢查成功，原有512MiB容量問題仍要按既有Archive-LAB01-v2.bat核對／封存後才單台重派；
本包沒有宣稱容量或0.4.64升級已解決。資料／身分／rollback保留，原產品與維護ZIP內容不變。
確認owner為SYSTEM／Administrators、其完整控制仍在，子樹無reparse，無並行安裝更新，
BAT／輸出目錄與已安裝Updater可信，才確認Y；不具備條件就選N。
不改PowerShell／Defender／App Control政策；若被公司政策阻擋，停止交MIS正式核准。
本工具尚未在LAB01執行；公司Windows／Defender／還原及完整升級仍待現場驗收。
'''


def main():
    folder=ROOT/'dist/lab01-updates-acl-repair-20261029';folder.mkdir(exist_ok=True)
    members={'Repair-LAB01-Updates-ACL.bat':render(),'README.txt':README.encode('utf-8-sig')}
    manifest={n:hashlib.sha256(b).hexdigest() for n,b in members.items()}
    members['MANIFEST-SHA256.json']=(json.dumps(manifest,indent=2)+'\n').encode('ascii')
    for n,b in members.items():(folder/n).write_bytes(b)
    archive=ROOT/'dist/GuardDesk-LAB01-Updates-ACL-Repair-20261029.zip'
    if archive.exists():raise FileExistsError('Preserve existing sealed updates repair archive')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for n,b in members.items():z.writestr(n,b)
    print(json.dumps(dict(artifact=str(archive),sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))


if __name__=='__main__':main()
