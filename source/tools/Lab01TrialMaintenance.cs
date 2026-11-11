// Fixed LAB01 maintenance coordinator. Direct Windows/.NET APIs; no script host.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Xml;

[assembly:AssemblyTitle("GuardDesk LAB01 Trial Maintenance")]
[assembly:AssemblyDescription("Fixed-identity recovery, Defender validation and startup observation; internal trial")]
[assembly:AssemblyCompany("GuardDesk")]
[assembly:AssemblyProduct("GuardDesk LAB01 Trial Maintenance")]
[assembly:AssemblyVersion("0.4.87.2")]
namespace GuardDeskMaintenance {
public class Review : Exception { public Review(string code):base(code){} }
public sealed class ChildResult { public int Exit; public string Text; }
// Evidence-only helpers: never interpret an alert as a confirmed false positive,
// and never serialize arbitrary exception messages, command lines or event XML.
public static class Diagnostics {
    public static string ErrorCode(Exception e) {
        if(e is Review)return e.Message;
        uint code=unchecked((uint)e.HResult);
        var native=e as System.ComponentModel.Win32Exception;
        if(native!=null&&native.NativeErrorCode>0&&native.NativeErrorCode<=65535)code=0x80070000|(uint)native.NativeErrorCode;
        switch(code) {
            case 0x800700E1:return "ANTIMALWARE_FILE_ACCESS_BLOCKED";
            case 0x800700E2:return "ANTIMALWARE_FILE_REMOVED";
            case 0x80070005:return "WINDOWS_ACCESS_DENIED";
            case 0x80070002:return "FILE_NOT_FOUND";
            case 0x80070003:return "DIRECTORY_NOT_FOUND";
            case 0x80070020:return "FILE_SHARING_VIOLATION";
            default:return "WINDOWS_API_OR_IO_ERROR";
        }
    }
    public static Dictionary<string,object> Event(string text,int id,long? record,DateTime? time) {
        Checks.Need(text!=null&&text.Length<=1048576,"EVENT_SIZE_LIMIT");
        var xml=Checks.Xml(text);
        var ns=new XmlNamespaceManager(xml.NameTable);ns.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event");
        var nodes=xml.SelectNodes("/e:Event/e:EventData/e:Data",ns);
        Checks.Need(nodes.Count<=128,"EVENT_FIELD_LIMIT");
        // Preserve the existing broad GuardDesk match, but never export raw XML.
        if(text.IndexOf("GuardDesk",StringComparison.OrdinalIgnoreCase)<0)return null;
        var row=new Dictionary<string,object>{{"event_id",id},{"record_id",record},{"time",time},{"remediation_confirmed",false}};
        var fields=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(XmlNode n in nodes) {
            string name=n.Attributes["Name"]==null?"":n.Attributes["Name"].Value;
            Checks.Need(!fields.ContainsKey(name),"EVENT_DUPLICATE_FIELD");fields[name]=n.InnerText;
        }
        string value;
        if(fields.TryGetValue("Threat Name",out value)&&Regex.IsMatch(value,@"\A[A-Za-z0-9_.!:/-]{1,160}\z"))row["threat_name"]=value;
        foreach(string name in new[]{"Threat ID","Severity ID","Category ID","Action ID","Error Code"})if(fields.TryGetValue(name,out value)&&Regex.IsMatch(value,@"\A(?:[0-9]{1,20}|0x[0-9a-fA-F]{1,8})\z"))row[name]=value;
        if(fields.TryGetValue("Path",out value)) {
            // Only classifications, not arbitrary private paths or registry contents.
            row["mentions_installed_agent"]=value.IndexOf(@"\GuardDeskPilot\USBControl\GuardDesk.exe",StringComparison.OrdinalIgnoreCase)>=0;
            row["mentions_guarddesk_task"]=value.IndexOf("GuardDesk-USBControl-"+RealTrial.Device,StringComparison.OrdinalIgnoreCase)>=0;
            var processes=new List<object>();
            foreach(Match m in Regex.Matches(value,@"\bprocess: pid:([0-9]{1,10}),ProcessStart:([0-9]{1,20})(?=\s|;|$)")) {
                Checks.Need(processes.Count<16,"EVENT_PROCESS_LIMIT");uint pid;long ft;
                if(uint.TryParse(m.Groups[1].Value,out pid)&&pid>0&&long.TryParse(m.Groups[2].Value,out ft)&&ft>0)
                    processes.Add(new{pid=pid,process_start_filetime=m.Groups[2].Value});
            }
            row["process_references"]=processes;
        }
        return row;
    }
    public static void MergeEvents(List<object> retained,List<object> current) {
        foreach(object item in current) {
            var row=Checks.Obj(item);object record;
            bool identified=row.TryGetValue("record_id",out record)&&record!=null;
            bool exists=identified&&retained.Any(x=>{var old=Checks.Obj(x);return old.ContainsKey("record_id")&&Equals(old["record_id"],record)&&Equals(old["event_id"],row["event_id"]);});
            if(exists)continue;
            Checks.Need(retained.Count<127,"EVENT_EVIDENCE_LIMIT");retained.Add(row);
        }
    }
    public static Dictionary<string,object> Process(Dictionary<string,object> raw,string image) {
        if(!string.Equals(Checks.Str(raw,"ExecutablePath"),image,StringComparison.OrdinalIgnoreCase))return null;
        var safe=new Dictionary<string,object>{{"image_role","installed_agent_image"},{"functional_role","unknown"}};
        foreach(string key in new[]{"ProcessId","ParentProcessId","SessionId"}) {
            object v;double n=raw.TryGetValue(key,out v)&&v is uint?(double)(uint)v:Checks.Number(raw,key);
            Checks.Need(n>=0&&n<=uint.MaxValue&&n==Math.Floor(n),"PROCESS_METADATA_INVALID");safe[key]=n;
        }
        string created=Checks.Str(raw,"CreationDate");
        Checks.Need(Regex.IsMatch(created,@"\A[0-9]{14}\.[0-9]{6}[+-][0-9]{3}\z"),"PROCESS_CREATION_TIME_INVALID");
        safe["CreationDate"]=created;return safe;
    }
    public static void CandidateGate() { throw new Review("CANDIDATE_087_ON_HOLD_NO_RETRY"); }
}
public interface ITrialSteps { void Check(); void Recover(); void Install(); void Observe(); }
public static class TrialSequence {
    public static void Run(ITrialSteps steps, Action<string> stage) {
        stage("candidate_check"); steps.Check();
        stage("recovery"); steps.Recover();
        stage("install"); steps.Install();
        stage("startup_observation"); steps.Observe();
    }
}
public static class Checks {
    public static void Need(bool value,string code) { if(!value)throw new Review(code); }
    public static string Str(Dictionary<string,object> d,string k) { object v;return d.TryGetValue(k,out v)&&v is string?(string)v:""; }
    public static Dictionary<string,object> Obj(object o) { var d=o as Dictionary<string,object>;Need(d!=null,"JSON_OBJECT_REQUIRED");return d; }
    public static double Number(Dictionary<string,object> d,string key) {
        object v;Need(d.TryGetValue(key,out v) && (v is int || v is long || v is double || v is decimal),"INVALID_NUMBER");
        double n=Convert.ToDouble(v,CultureInfo.InvariantCulture);Need(!double.IsNaN(n)&&!double.IsInfinity(n),"INVALID_NUMBER");return n;
    }
    public static JavaScriptSerializer Serializer(int max) { return new JavaScriptSerializer{MaxJsonLength=max,RecursionLimit=40}; }
    public static string Plain(string path) {
        string full=Path.GetFullPath(path);
        for(string p=full;!string.IsNullOrEmpty(p);p=Path.GetDirectoryName(p)) {
            // File.GetAttributes preserves access-denied, unlike File.Exists.
            try { Need((File.GetAttributes(p)&FileAttributes.ReparsePoint)==0,"REPARSE_PATH_REFUSED"); }
            catch(FileNotFoundException){} catch(DirectoryNotFoundException){}
        }
        return full;
    }
    public static string Child(string root,string relative) {
        Need(!string.IsNullOrWhiteSpace(relative),"INVALID_PAYLOAD_PATH");
        Need(relative.IndexOfAny(new[]{':','\r','\n','"','\0'})<0,"INVALID_PAYLOAD_PATH");
        Need(!Path.IsPathRooted(relative),"INVALID_PAYLOAD_PATH");
        string[] parts=relative.Replace('\\','/').Split('/');
        Need(parts.All(p=>p.Length>0&&p!="."&&p!=".."&&!p.EndsWith(".")&&!p.EndsWith(" ")),"INVALID_PAYLOAD_PATH");
        string parent=Plain(root).TrimEnd('\\')+"\\",full=Plain(Path.Combine(root,relative));
        Need(full.StartsWith(parent,StringComparison.OrdinalIgnoreCase),"PAYLOAD_PATH_ESCAPE");return full;
    }
    public static Dictionary<string,object> Json(string path,int bound) {
        Need(bound>0&&bound<=4194304,"INVALID_JSON_BOUND");Plain(path);
        using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            Need(f.Length<=bound,"STATE_SIZE_LIMIT");byte[] bytes=new byte[bound+1];int used=0,n;
            while(used<bytes.Length&&(n=f.Read(bytes,used,bytes.Length-used))>0)used+=n;
            Need(used<=bound,"STATE_SIZE_LIMIT");
            try{return Obj(Serializer(bound).DeserializeObject(new UTF8Encoding(false,true).GetString(bytes,0,used).TrimStart('\ufeff')));}
            catch(Review){throw;}catch{throw new Review("INVALID_JSON_CONTENTS_OMITTED");}
        }
    }
    public static string Hash(string path) { Plain(path);using(var f=File.OpenRead(path))using(var h=SHA256.Create())return Hex(h.ComputeHash(f)); }
    public static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-","").ToLowerInvariant(); }
    public static List<string> Files(string root) {
        var pending=new Queue<string>();var files=new List<string>();pending.Enqueue(Plain(root));int count=0;
        while(pending.Count>0)foreach(string entry in Directory.EnumerateFileSystemEntries(pending.Dequeue())) {
            Need(++count<=4096,"INVENTORY_LIMIT");Plain(entry);
            if((File.GetAttributes(entry)&FileAttributes.Directory)!=0)pending.Enqueue(entry);else files.Add(entry);
        }
        return files;
    }
    public static void Inventory(string root,Dictionary<string,object> manifest) {
        List<string> files=Files(root);Need(files.Count==manifest.Count,"INVENTORY_MISMATCH");
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var pair in manifest) {
            string p=Child(root,pair.Key);Need(names.Add(p),"DUPLICATE_PAYLOAD_PATH");
            Need(pair.Value is string && Regex.IsMatch((string)pair.Value,"^[a-f0-9]{64}$"),"INVALID_PAYLOAD_HASH");
            try { Need(Hash(p)==(string)pair.Value,"PAYLOAD_HASH_MISMATCH"); }
            catch(IOException e) { if(pair.Key.Length<=512)e.Data["guarddesk_payload_entry"]=pair.Key;throw; }
        }
    }
    public static string ExclusionVerdict(int code,string text) {
        bool no=Regex.IsMatch(text,@"\bis not excluded\.?(?:\s|$)",RegexOptions.IgnoreCase|RegexOptions.Multiline);
        bool yes=Regex.IsMatch(text,@"\bis excluded\.",RegexOptions.IgnoreCase|RegexOptions.Multiline);
        return code==1&&no&&!yes?"not_excluded":code==0&&yes&&!no?"excluded":"unknown";
    }
    public static void CleanScan(int code,string text) {Need(code==0&&text.IndexOf("found no threats.",StringComparison.OrdinalIgnoreCase)>=0,"SCAN_REVIEW_REQUIRED");}
    public static void Identity(Dictionary<string,object> d,bool marker,bool final) {
        Need(Str(d,"device_id")==RealTrial.Device&&Str(d,"server")==RealTrial.Server&&Str(d,"install_profile")=="remote-only-trial-v1","TRIAL_IDENTITY_MISMATCH");
        if(marker)Need(final?Str(d,"version")=="0.4.87":new[]{"0.4.85","0.4.86"}.Contains(Str(d,"version")),"MACHINE_VERSION_MISMATCH");
    }
    public static int Health(Dictionary<string,object> d,double now,int oldPid) {
        double pid=Number(d,"pid"),stamp=Number(d,"time");
        Need(Str(d,"version")=="0.4.87"&&pid>0&&pid<=int.MaxValue&&pid==Math.Floor(pid),"HEALTH_VERSION_PID_MISMATCH");
        Need(now-stamp<=20&&stamp<=now+5,"HEALTH_STALE");
        Need(oldPid==0||oldPid==(int)pid,"WORKER_RESTARTED");return (int)pid;
    }
    public static string Quote(string arg) {
        Need(arg.IndexOfAny(new[]{'"','\r','\n','\0'})<0&&!arg.EndsWith("\\"),"INVALID_FIXED_ARGUMENT");return "\""+arg+"\"";
    }
    public static XmlDocument Xml(string text) {
        var settings=new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=1048576};
        var doc=new XmlDocument{XmlResolver=null};using(var r=XmlReader.Create(new StringReader(text),settings))doc.Load(r);return doc;
    }
}
public static class WindowsApi {
    public static Dictionary<string,object> Query(string scope,string query,string[] keys) {
        var options=new EnumerationOptions{ReturnImmediately=false,Timeout=TimeSpan.FromSeconds(20)};
        using(var search=new ManagementObjectSearcher(new ManagementScope(scope),new ObjectQuery(query),options))
        using(var result=search.Get()) {
            Checks.Need(result.Count==1,"WMI_SINGLE_RESULT_REQUIRED");
            foreach(ManagementBaseObject obj in result)using(obj) {
                var d=new Dictionary<string,object>();foreach(string key in keys)d[key]=obj[key];return d;
            }
        }throw new Review("WMI_NO_RESULT");
    }
    public static Dictionary<string,object> Defender() {
        var status=Query(@"root\Microsoft\Windows\Defender","SELECT * FROM MSFT_MpComputerStatus",new[]{"AMRunningMode","AMProductVersion","AMEngineVersion","AntivirusSignatureVersion","AntivirusEnabled","RealTimeProtectionEnabled","BehaviorMonitorEnabled","IoavProtectionEnabled","IsTamperProtected"});
        Checks.Need(Checks.Str(status,"AMRunningMode")=="Normal","DEFENDER_NOT_ACTIVE");
        foreach(string k in new[]{"AntivirusEnabled","RealTimeProtectionEnabled","BehaviorMonitorEnabled","IoavProtectionEnabled"})Checks.Need(status[k] is bool&&(bool)status[k],"DEFENDER_PROTECTION_NOT_ACTIVE");
        return status;
    }
    public static ChildResult Run(string exe,string[] arguments,int timeout,bool killOnTimeout) {
        Checks.Plain(exe);
        var info=new ProcessStartInfo(exe,string.Join(" ",arguments.Select(Checks.Quote))){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var p=new Process{StartInfo=info}) {
            Checks.Need(p.Start(),"CHILD_START_FAILED");
            var stdout=Task.Factory.StartNew(()=>ReadBounded(p.StandardOutput));
            var stderr=Task.Factory.StartNew(()=>ReadBounded(p.StandardError));
            if(!p.WaitForExit(timeout)) {
                // Kill only our read-only exclusion query. Never terminate installer/recovery.
                if(killOnTimeout)p.Kill();throw new Review("CHILD_TIMEOUT_PRESERVE_STATE");
            }
            Checks.Need(Task.WaitAll(new Task[]{stdout,stderr},10000),"CHILD_OUTPUT_TIMEOUT");
            return new ChildResult{Exit=p.ExitCode,Text=stdout.Result+stderr.Result};
        }
    }
    static string ReadBounded(StreamReader r) {
        var b=new StringBuilder();char[] buf=new char[4096];int n;bool overflow=false;
        while((n=r.Read(buf,0,buf.Length))>0) {if(b.Length+n<=1048576)b.Append(buf,0,n);else overflow=true;}
        if(overflow)throw new Review("CHILD_OUTPUT_LIMIT");return b.ToString();
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct TrustFile {public uint size;[MarshalAs(UnmanagedType.LPWStr)]public string path;public IntPtr file;public IntPtr subject;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct TrustData {public uint size;public IntPtr callback;public IntPtr sip;public uint ui;public uint revocation;public uint choice;public IntPtr file;public uint action;public IntPtr state;public IntPtr url;public uint flags;public uint context;}
    [DllImport("wintrust.dll",ExactSpelling=true)]static extern int WinVerifyTrust(IntPtr hwnd,ref Guid action,ref TrustData data);
    public static void MicrosoftSigned(string path) {
        Checks.Plain(path);var file=new TrustFile{size=(uint)Marshal.SizeOf(typeof(TrustFile)),path=path};
        IntPtr memory=Marshal.AllocHGlobal(Marshal.SizeOf(file));Marshal.StructureToPtr(file,memory,false);
        var data=new TrustData{size=(uint)Marshal.SizeOf(typeof(TrustData)),ui=2,choice=1,file=memory,action=1,flags=0x1000};
        Guid action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        try {
            Checks.Need(WinVerifyTrust(new IntPtr(-1),ref action,ref data)==0,"DEFENDER_SIGNATURE_NOT_VALID");
            using(var cert=new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
                Checks.Need(cert.GetNameInfo(X509NameType.SimpleName,false)=="Microsoft Corporation"||cert.GetNameInfo(X509NameType.SimpleName,false)=="Microsoft Windows Publisher","DEFENDER_PUBLISHER_MISMATCH");
        }finally{data.action=2;WinVerifyTrust(new IntPtr(-1),ref action,ref data);Marshal.DestroyStructure(memory,typeof(TrustFile));Marshal.FreeHGlobal(memory);}
    }
    public static List<object> DefenderEvents(DateTime start) {
        string time=start.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ",CultureInfo.InvariantCulture);
        string xpath="*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119) and TimeCreated[@SystemTime >= '"+time+"']]]";
        var rows=new List<object>();int count=0;var timer=Stopwatch.StartNew();
        using(var reader=new EventLogReader(new EventLogQuery("Microsoft-Windows-Windows Defender/Operational",PathType.LogName,xpath){ReverseDirection=true})) {
            while(true) {
                Checks.Need(timer.Elapsed.TotalSeconds<20,"EVENT_QUERY_TIMEOUT");
                var record=reader.ReadEvent(TimeSpan.FromMilliseconds(Math.Max(1,Math.Min(15000,20000-timer.Elapsed.TotalMilliseconds))));
                if(record==null)break;
                using(record) {
                Checks.Need(++count<128,"EVENT_WINDOW_LIMIT");string xml=record.ToXml();Checks.Need(xml.Length<=1048576,"EVENT_SIZE_LIMIT");
                var safe=Diagnostics.Event(xml,record.Id,record.RecordId,record.TimeCreated);if(safe!=null)rows.Add(safe);
                }
            }
        }return rows;
    }
    public static List<object> AgentProcesses(string image) {
        var rows=new List<object>();int count=0;
        var options=new EnumerationOptions{ReturnImmediately=false,Timeout=TimeSpan.FromSeconds(20)};
        using(var search=new ManagementObjectSearcher(new ManagementScope(@"root\cimv2"),new ObjectQuery("SELECT ProcessId,ParentProcessId,SessionId,CreationDate,ExecutablePath FROM Win32_Process WHERE Name='GuardDesk.exe'"),options))
        using(var result=search.Get())foreach(ManagementBaseObject obj in result)using(obj) {
            Checks.Need(++count<=32,"PROCESS_SNAPSHOT_LIMIT");
            var raw=new Dictionary<string,object>();foreach(string key in new[]{"ProcessId","ParentProcessId","SessionId","CreationDate","ExecutablePath"}) {
                object v=obj[key];raw[key]=v is uint?(object)(long)(uint)v:v;
            }
            var safe=Diagnostics.Process(raw,image);if(safe!=null)rows.Add(safe);
        }
        return rows;
    }
    public static void ScheduledWorker(string did,string image) {
        object service=null,folder=null,task=null,def=null,principal=null;
        try {
            service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service",true));dynamic s=service;s.Connect();folder=s.GetFolder("\\");dynamic f=folder;task=f.GetTask("GuardDesk-USBControl-"+did);dynamic t=task;
            Checks.Need((int)t.State==4,"SYSTEM_TASK_NOT_RUNNING");def=t.Definition;dynamic d=def;principal=d.Principal;dynamic pr=principal;
            string user=(string)pr.UserId;Checks.Need(new[]{"SYSTEM","NT AUTHORITY\\SYSTEM","S-1-5-18"}.Contains(user,StringComparer.OrdinalIgnoreCase),"TASK_NOT_SYSTEM");
            XmlDocument xml=Checks.Xml((string)t.Xml);var ns=new XmlNamespaceManager(xml.NameTable);ns.AddNamespace("t","http://schemas.microsoft.com/windows/2004/02/mit/task");
            var actions=xml.SelectNodes("/t:Task/t:Actions/t:Exec",ns);Checks.Need(actions.Count==1,"TASK_ACTION_COUNT");
            Checks.Need(string.Equals(actions[0].SelectSingleNode("t:Command",ns).InnerText,image,StringComparison.OrdinalIgnoreCase),"TASK_IMAGE_MISMATCH");
        }finally{foreach(object o in new[]{principal,def,task,folder,service})if(o!=null&&Marshal.IsComObject(o))Marshal.FinalReleaseComObject(o);}
    }
}
public sealed class RealTrial : ITrialSteps {
    public const string Device="eea0d7f81091fe91372a924c",Server="https://192.168.50.30:17897";
    readonly string root,expanded,zip,program,data;readonly Dictionary<string,object> report;
    Dictionary<string,object> receipt,files;string tool,toolHash;DateTime? observationStart;
    public RealTrial(string root,Dictionary<string,object> report) {
        this.root=Checks.Plain(root);this.report=report;expanded=Path.Combine(root,@"candidate\expanded");zip=Path.Combine(root,@"candidate\Candidate.zip");
        program=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"GuardDeskPilot");
        data=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),@"GuardDeskPilot\USBControl",Device);
    }
    public void Check() {
        // Source-only diagnostics revision. The detected 087 candidate cannot be retried.
        Diagnostics.CandidateGate();
        Console.WriteLine("[1/4] Checking exact candidate, Defender and scan scope...");
        Checks.Identity(Checks.Json(Path.Combine(program,"machine-endpoint.json"),65536),true,false);
        Checks.Identity(Checks.Json(Path.Combine(data,"config.json"),65536),false,false);
        string rp=Path.Combine(root,@"candidate\package-receipt.json");
        Checks.Need(Checks.Hash(rp)==CandidateIdentity.ReceiptHash,"RECEIPT_HASH_MISMATCH");receipt=Checks.Json(rp,1048576);
        Checks.Need(Checks.Hash(zip)==CandidateIdentity.ZipHash&&Checks.Str(receipt,"zip_sha256")==CandidateIdentity.ZipHash,"ZIP_HASH_MISMATCH");
        Checks.Inventory(expanded,Checks.Obj(receipt["files"]));
        var manifest=Checks.Json(Path.Combine(expanded,"endpoint-files.json"),1048576);Checks.Need(Checks.Str(manifest,"version")=="0.4.87","WRONG_CANDIDATE_VERSION");files=Checks.Obj(manifest["files"]);
        Checks.Need(files.Count==1070,"CANDIDATE_FILE_COUNT");Checks.Inventory(Path.Combine(expanded,"GuardDesk"),files);
        var status=WindowsApi.Defender();report["defender_before"]=status;
        var prefs=WindowsApi.Query(@"root\Microsoft\Windows\Defender","SELECT DisableArchiveScanning FROM MSFT_MpPreference",new[]{"DisableArchiveScanning"});
        Checks.Need(prefs["DisableArchiveScanning"] is bool&&!(bool)prefs["DisableArchiveScanning"],"ARCHIVE_SCAN_DISABLED_OR_UNKNOWN");
        string version=Checks.Str(status,"AMProductVersion");Checks.Need(Regex.IsMatch(version,@"^\d+\.\d+\.\d+\.\d+$"),"INVALID_PLATFORM_VERSION");
        tool=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),@"Microsoft\Windows Defender\Platform",version+"-0","MpCmdRun.exe");
        try{File.GetAttributes(tool);}catch(FileNotFoundException){tool=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"Windows Defender\MpCmdRun.exe");}catch(DirectoryNotFoundException){tool=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"Windows Defender\MpCmdRun.exe");}
        WindowsApi.MicrosoftSigned(tool);toolHash=Checks.Hash(tool);report["defender_tool_sha256"]=toolHash;
        observationStart=DateTime.UtcNow;report["observation_started"]=observationStart.Value.ToString("o");
        string selfHash=Checks.Hash(Assembly.GetExecutingAssembly().Location);report["maintenance_sha256"]=selfHash;
        Scope(new[]{zip,Assembly.GetExecutingAssembly().Location}.Concat(Checks.Files(expanded)).ToList(),"candidate_scope");
        Scan(zip,"candidate_zip_scan");Scan(expanded,"expanded_scan");Scan(Assembly.GetExecutingAssembly().Location,"maintenance_scan");
        Checks.Need(Checks.Hash(Assembly.GetExecutingAssembly().Location)==selfHash,"MAINTENANCE_CHANGED_DURING_SCAN");
        Checks.Need(Checks.Hash(zip)==CandidateIdentity.ZipHash,"ZIP_CHANGED_DURING_SCAN");Checks.Inventory(expanded,Checks.Obj(receipt["files"]));CheckEvents();
        report["candidate_check"]="STATIC_SCAN_NO_THREATS_EXCLUSIONS_CHECKED";
    }
    void Scope(List<string> paths,string key) {
        var rows=new List<object>();report[key]=rows;var timer=Stopwatch.StartNew();int count=0;
        Checks.Need(Checks.Hash(tool)==toolHash,"DEFENDER_TOOL_CHANGED");
        foreach(string p in paths) {
            Checks.Need(timer.Elapsed.TotalSeconds<360,"SCOPE_TIME_LIMIT");
            var r=WindowsApi.Run(tool,new[]{"-CheckExclusion","-Path",p},15000,true);string verdict=Checks.ExclusionVerdict(r.Exit,r.Text);
            rows.Add(new{path=p,exit_code=r.Exit,verdict=verdict});Checks.Need(verdict=="not_excluded","SCOPE_EXCLUDED_OR_UNKNOWN");
            if(++count%25==0)Console.WriteLine("Scope {0}/{1}",count,paths.Count);
        }report[key+"_count"]=count;
    }
    void Scan(string path,string key) {
        Console.WriteLine("Scanning: "+path);Checks.Need(Checks.Hash(tool)==toolHash,"DEFENDER_TOOL_CHANGED");
        var r=WindowsApi.Run(tool,new[]{"-Scan","-ScanType","3","-File",path},600000,false);
        report[key]=new{exit_code=r.Exit,output=r.Text};Checks.CleanScan(r.Exit,r.Text);
    }
    public void Recover() {
        Console.WriteLine("[2/4] Preserving exact interrupted transaction and identity...");
        Checks.Inventory(expanded,Checks.Obj(receipt["files"]));CheckEvents();report["recovery_attempted"]=true;
        var r=WindowsApi.Run(Path.Combine(expanded,@"Recovery\GuardDeskInstallRecovery.exe"),new[]{"--prepare"},120000,false);
        report["recovery_exit_code"]=r.Exit;Dictionary<string,object> body;
        try{body=Checks.Obj(Checks.Serializer(1048576).DeserializeObject(r.Text));}catch{throw new Review("RECOVERY_OUTPUT_INVALID");}
        var safe=new Dictionary<string,object>();foreach(string k in new[]{"result","code","error_type","winerror","permission_review","archive","program_archive","identity_preserved"})if(body.ContainsKey(k))safe[k]=body[k];report["recovery"]=safe;
        Checks.Need(r.Exit==0&&Checks.Str(body,"result")=="RECOVERY_PREPARED_NOT_INSTALLED","RECOVERY_REVIEW_REQUIRED");CheckEvents();
    }
    public void Install() {
        Console.WriteLine("[3/4] Installing the same-identity 0.4.87 trial...");Checks.Inventory(Path.Combine(expanded,"GuardDesk"),files);
        Checks.Identity(Checks.Json(Path.Combine(data,"config.json"),65536),false,false);report["install_attempted"]=true;
        var r=WindowsApi.Run(Path.Combine(expanded,@"GuardDesk\GuardDesk.exe"),new[]{"usb-install","--config",Path.Combine(data,"config.json"),"--action","Install"},600000,false);
        report["install_exit_code"]=r.Exit;
        var stage=Regex.Match(r.Text,@"GUARDDESK_STAGE=(staging|switching|register_tasks|initial_policy|complete|rollback|preflight)\b");
        if(stage.Success)report["installer_stage"]=stage.Groups[1].Value;
        // Do not persist arbitrary installer text, which could contain private paths/config.
        Checks.Need(r.Exit==0,"INSTALL_INCOMPLETE_PRESERVE_TRANSACTION");CheckEvents();
    }
    public void Observe() {
        Console.WriteLine("[4/4] Observing startup and installed files...");var samples=new List<object>();report["samples"]=samples;int pid=0;double first=0,last=0;
        string installed=Path.Combine(program,"USBControl"),image=Path.Combine(installed,"GuardDesk.exe");var elapsed=Stopwatch.StartNew();
        for(int i=0;i<7;i++) {
            report["operation"]="health_observation";CheckEvents();
            var health=Checks.Json(Path.Combine(data,"native-health.json"),65536);double now=(DateTime.UtcNow-new DateTime(1970,1,1)).TotalSeconds;
            pid=Checks.Health(health,now,pid);var process=WindowsApi.Query(@"root\cimv2","SELECT ExecutablePath,ProcessId,ParentProcessId,SessionId,CreationDate FROM Win32_Process WHERE ProcessId="+pid.ToString(CultureInfo.InvariantCulture),new[]{"ExecutablePath","ProcessId","ParentProcessId","SessionId","CreationDate"});
            Checks.Need(string.Equals(Checks.Str(process,"ExecutablePath"),image,StringComparison.OrdinalIgnoreCase)&&Convert.ToInt32(process["SessionId"])==0,"HEALTH_PROCESS_MISMATCH");
            last=Checks.Number(health,"time");if(i==0)first=last;samples.Add(new{pid=pid,session_id=0,version="0.4.87",time=last,process=Diagnostics.Process(process,image)});Console.WriteLine("Health {0}/7",i+1);if(i<6)Thread.Sleep(10000);
        }
        CheckEvents();Checks.Need(elapsed.Elapsed.TotalSeconds>=60&&last>first,"HEALTH_NOT_ADVANCING");report["operation"]="scheduled_worker_check";WindowsApi.ScheduledWorker(Device,image);
        var journal=Checks.Json(Path.Combine(data,"install-transaction.json"),65536);Checks.Need(Checks.Str(journal,"phase")=="complete"&&Checks.Str(journal,"version")=="0.4.87","JOURNAL_NOT_COMPLETE");
        var startup=Checks.Json(Path.Combine(data,"native-startup.json"),65536);Checks.Need(Checks.Str(startup,"version")=="0.4.87"&&Checks.Str(startup,"phase")=="running"&&Checks.Str(startup,"state")=="entered"&&Checks.Number(startup,"pid")==pid,"STARTUP_MISMATCH");
        report["startup"]=new{version="0.4.87",phase="running",state="entered",pid=pid};report["defender_after"]=WindowsApi.Defender();
        CheckEvents();report["operation"]="installed_inventory_before_scan";Checks.Inventory(installed,files);
        report["operation"]="installed_exclusion_scope";Scope(Checks.Files(installed),"installed_scope");
        CheckEvents();report["operation"]="installed_scan";Scan(installed,"installed_scan");
        CheckEvents();report["operation"]="installed_inventory_after_scan";Checks.Inventory(installed,files);
        Checks.Identity(Checks.Json(Path.Combine(program,"machine-endpoint.json"),65536),true,true);CheckEvents();
    }
    public void CheckEvents() {
        if(!observationStart.HasValue)return;
        List<object> retained;
        if(report.ContainsKey("defender_events"))retained=(List<object>)report["defender_events"];
        else {retained=new List<object>();report["defender_events"]=retained;}
        Diagnostics.MergeEvents(retained,WindowsApi.DefenderEvents(observationStart.Value));report["event_query"]="read";
        Checks.Need(retained.Count==0,"DEFENDER_EVENT_REVIEW_REQUIRED");
    }
    public void Snapshot() {
        if(!(bool)report["install_attempted"])return;
        try {report["process_snapshot"]=WindowsApi.AgentProcesses(Path.Combine(program,@"USBControl\GuardDesk.exe"));}
        catch(Exception e){report["process_snapshot_error"]=new{code=Diagnostics.ErrorCode(e),hresult=e.HResult.ToString("X8")};}
        var states=new Dictionary<string,object>();report["installation_state"]=states;
        foreach(string name in new[]{"install-transaction.json","native-health.json","native-startup.json"})try{
            states[name]=Metadata(Checks.Json(Path.Combine(data,name),65536));
        }catch(Exception e){states[name]=new{read_error=e.GetType().Name,hresult=e.HResult.ToString("X8")};}
    }
    public static Dictionary<string,object> Metadata(Dictionary<string,object> source) {
        var safe=new Dictionary<string,object>();
        foreach(string k in new[]{"version","id","phase","state"}) {
            string s=Checks.Str(source,k);bool allowed=k=="version"?Regex.IsMatch(s,@"^\d{1,5}\.\d{1,5}\.\d{1,5}$"):k=="id"?Regex.IsMatch(s,"^[a-f0-9]{16}$"):k=="state"?new[]{"entered","failed"}.Contains(s):new[]{"staging","switching","register_tasks","initial_policy","complete","rolled_back","failed_before_switch","construct_supervisor","start_supervisor","running","stopped"}.Contains(s);
            if(allowed)safe[k]=s;
        }
        foreach(string k in new[]{"pid","time","started"})if(source.ContainsKey(k))try{safe[k]=Checks.Number(source,k);}catch(Review){}
        return safe;
    }
}
public static class Program {
    public static int Main(string[] args) {
        Console.OutputEncoding=new UTF8Encoding(false);
        var report=new Dictionary<string,object>{{"format",1},{"tool","GuardDesk LAB01 compiled maintenance 002"},{"version","0.4.87"},{"started",DateTime.UtcNow.ToString("o")},{"result","REVIEW_REQUIRED"},{"recovery_attempted",false},{"install_attempted",false},{"defender_settings_changed",false},{"script_policy_changed",false},{"script_host_used",false},{"deployable",false}};
        string root=AppDomain.CurrentDomain.BaseDirectory;RealTrial trial=null;
        try {
            Checks.Need(args.Length==1&&args[0]=="--run","USAGE_RUN_ONLY");
            Checks.Need(Environment.MachineName.Equals("LAB01",StringComparison.OrdinalIgnoreCase),"LAB01_ONLY");
            using(var id=WindowsIdentity.GetCurrent())Checks.Need(new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator),"ADMINISTRATOR_REQUIRED");
            trial=new RealTrial(root,report);TrialSequence.Run(trial,stage=>report["stage"]=stage);report["result"]="LAB01_STARTUP_OBSERVED_NOT_FULL_ACCEPTANCE";
        } catch(Exception e) {
            report["error_type"]=e.GetType().Name;report["error_code"]=Diagnostics.ErrorCode(e);report["hresult"]=e.HResult.ToString("X8");
            var relative=e.Data["guarddesk_payload_entry"] as string;if(relative!=null)report["failed_payload_entry"]=relative;
        }
        finally {
            if(trial!=null)trial.Snapshot();
            if(trial!=null)try{trial.CheckEvents();}catch(Exception e){report["result"]="REVIEW_REQUIRED";report["event_query_error"]=e is Review?e.Message:e.GetType().Name;}
            report["finished"]=DateTime.UtcNow.ToString("o");
            string path=Path.Combine(root,"LAB01-Test-"+Guid.NewGuid().ToString("N")+".json");
            try {using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None))using(var w=new StreamWriter(f,new UTF8Encoding(false)))w.Write(Checks.Serializer(4194304).Serialize(report));Console.WriteLine("Report="+path);}
            catch(Exception e){report["result"]="REVIEW_REQUIRED";Console.WriteLine("REPORT_WRITE_FAILED="+e.GetType().Name);}
            Console.WriteLine("Result="+report["result"]);if(report.ContainsKey("error_code"))Console.WriteLine("Error="+report["error_code"]);
        }return (string)report["result"]=="LAB01_STARTUP_OBSERVED_NOT_FULL_ACCEPTANCE"?0:1;
    }
}}
