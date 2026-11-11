// Read-only, fixed LAB01 incident. No Agent loading, process start, network,
// Defender scan/settings, registry write, task change, or script host.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Xml;

[assembly:AssemblyTitle("GuardDesk LAB01 Incident Evidence")]
[assembly:AssemblyDescription("Read-only fixed incident evidence; internal diagnostic")]
[assembly:AssemblyVersion("1.0.0.0")]
namespace GuardDeskIncident {
public sealed class EvidenceLimit:Exception {public EvidenceLimit(string code):base(code){}}
public static class Evidence {
    public const string Begin="2026-11-03T05:40:00.000Z",End="2026-11-03T05:55:00.000Z";
    public const string TaskName="GuardDesk-USBControl-eea0d7f81091fe91372a924c";
    public static readonly Dictionary<uint,long> Starts=new Dictionary<uint,long>{{7780,134381583131634652},{28208,134381583224646976}};
    public static void Need(bool ok,string code){if(!ok)throw new EvidenceLimit(code);}
    public static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=1048576,RecursionLimit=20};}
    public static Dictionary<string,string> Fields(string text) {
        Need(text!=null&&text.Length<=1048576,"EVENT_SIZE_LIMIT");
        var settings=new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=1048576};
        var doc=new XmlDocument{XmlResolver=null};using(var reader=XmlReader.Create(new StringReader(text),settings))doc.Load(reader);
        var ns=new XmlNamespaceManager(doc.NameTable);ns.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event");
        var nodes=doc.SelectNodes("/e:Event/e:EventData/e:Data",ns);Need(nodes.Count<=128,"EVENT_FIELD_LIMIT");
        var fields=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(XmlNode node in nodes){string key=node.Attributes["Name"]==null?"":node.Attributes["Name"].Value;Need(!fields.ContainsKey(key),"DUPLICATE_EVENT_FIELD");fields[key]=node.InnerText;}
        return fields;
    }
    public static string Get(Dictionary<string,string> d,string key){string value;return d.TryGetValue(key,out value)?value:"";}
    public static uint? Pid(string text) {
        uint value;if(Regex.IsMatch(text,@"\A0x[0-9a-fA-F]{1,8}\z"))return uint.TryParse(text.Substring(2),NumberStyles.HexNumber,CultureInfo.InvariantCulture,out value)?(uint?)value:null;
        return Regex.IsMatch(text,@"\A[0-9]{1,10}\z")&&uint.TryParse(text,out value)?(uint?)value:null;
    }
    public static string ImageClass(string image) {
        string program=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"GuardDeskPilot\USBControl\GuardDesk.exe");
        if(string.Equals(image,program,StringComparison.OrdinalIgnoreCase))return "installed_guarddesk_agent";
        string system=Environment.GetFolderPath(Environment.SpecialFolder.System);
        foreach(string name in new[]{"svchost.exe","taskeng.exe","taskhostw.exe","consent.exe"})
            if(string.Equals(image,Path.Combine(system,name),StringComparison.OrdinalIgnoreCase))return "windows_"+Path.GetFileNameWithoutExtension(name);
        return "other_or_unavailable_path_omitted";
    }
    public static string Role(string image,string command) {
        if(ImageClass(image)!="installed_guarddesk_agent")return "unknown";
        // Read only an exact executable + first fixed command. Never retain argv.
        string head="(?:\""+Regex.Escape(image)+"\"|"+Regex.Escape(image)+")";
        var m=Regex.Match(command,"\\A"+head+@"\s+(usb-worker|machine-session)(?=\s|\z)",RegexOptions.IgnoreCase);
        if(!m.Success)return "unknown";
        return m.Groups[1].Value.Equals("machine-session",StringComparison.OrdinalIgnoreCase)?"machine_session_helper":"native_worker";
    }
    public static Dictionary<string,object> Parse(string channel,int id,long? record,DateTime? time,string text) {
        Need(time.HasValue,"EVENT_TIME_MISSING");DateTime utc=time.Value.ToUniversalTime();
        if(utc<DateTime.Parse(Begin,null,DateTimeStyles.AdjustToUniversal)||utc>DateTime.Parse(End,null,DateTimeStyles.AdjustToUniversal))return null;
        var f=Fields(text);var row=new Dictionary<string,object>{{"event_id",id},{"record_id",record},{"time_utc",utc.ToString("o")}};
        if(channel=="Security") {
            if(id!=4688)return null;uint? pid=Pid(Get(f,"NewProcessId"));
            if(!pid.HasValue||!Starts.ContainsKey(pid.Value))return null;
            // PID alone is not historical identity. Preserve the time delta and
            // flag ambiguous reuse; do not label it as the same process by PID.
            double delta=(utc-DateTime.FromFileTimeUtc(Starts[pid.Value])).TotalSeconds;
            string image=Get(f,"NewProcessName");
            row["pid"]=pid.Value;row["parent_pid"]=Pid(Get(f,"ProcessId"));
            row["image_class"]=ImageClass(image);row["parent_image_class"]=ImageClass(Get(f,"ParentProcessName"));
            row["creation_event_delta_seconds"]=delta;
            row["matches_reported_start_within_2_seconds"]=Math.Abs(delta)<=2;
            row["role_from_fixed_command"]=Role(image,Get(f,"CommandLine"));
            row["parent_process_identity_verified"]=false;
            return row;
        }
        if(channel=="Microsoft-Windows-Windows Defender/Operational") {
            if(id<1116||id>1119||text.IndexOf("GuardDesk",StringComparison.OrdinalIgnoreCase)<0)return null;
            string name=Get(f,"Threat Name");if(Regex.IsMatch(name,@"\A[A-Za-z0-9_.!:/-]{1,160}\z"))row["threat_name"]=name;
            Guid detection;if(Guid.TryParse(Get(f,"Detection ID"),out detection))row["detection_id"]=detection.ToString("D");
            foreach(string key in new[]{"Threat ID","Action ID","Error Code","Severity ID","Category ID"}) {
                string v=Get(f,key);if(Regex.IsMatch(v,@"\A(?:[0-9]{1,20}|0x[0-9a-fA-F]{1,8})\z"))row[key]=v;
            }
            row["event_is_action_record"]=id==1117;row["remediation_success_not_inferred"]=true;
            row["process_image_class"]=ImageClass(Get(f,"Process Name"));
            string path=Get(f,"Path");
            row["mentions_installed_agent"]=path.IndexOf(@"\GuardDeskPilot\USBControl\GuardDesk.exe",StringComparison.OrdinalIgnoreCase)>=0;
            row["mentions_exact_task"]=path.IndexOf(TaskName,StringComparison.OrdinalIgnoreCase)>=0;
            var references=new List<object>();
            foreach(Match m in Regex.Matches(path,@"\bprocess: pid:([0-9]{1,10}),ProcessStart:([0-9]{1,20})(?=\s|;|$)")) {
                uint? pid=Pid(m.Groups[1].Value);long ft;
                if(pid.HasValue&&Starts.ContainsKey(pid.Value)&&long.TryParse(m.Groups[2].Value,out ft)) {
                    Need(references.Count<16,"PROCESS_REFERENCE_LIMIT");
                    references.Add(new{pid=pid.Value,process_start_filetime=m.Groups[2].Value,matches_reported_start=Starts[pid.Value]==ft});
                }
            }
            row["process_references"]=references;return row;
        }
        if(channel=="Microsoft-Windows-TaskScheduler/Operational") {
            string task=Get(f,"TaskName");if(!task.Equals("\\"+TaskName,StringComparison.OrdinalIgnoreCase)&&!task.Equals(TaskName,StringComparison.OrdinalIgnoreCase))return null;
            foreach(string key in new[]{"ProcessID","EnginePID","ResultCode"}){uint? n=Pid(Get(f,key));if(n.HasValue)row[key]=n.Value;}
            row["exact_guarddesk_task"]=true;return row;
        }
        throw new EvidenceLimit("UNKNOWN_FIXED_CHANNEL");
    }
    public static string Query(string channel) {
        string ids=channel=="Security"?"EventID=4688":channel=="Microsoft-Windows-Windows Defender/Operational"?"EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119":channel=="Microsoft-Windows-TaskScheduler/Operational"?"EventID=100 or EventID=102 or EventID=200 or EventID=201 or EventID=203":null;
        Need(ids!=null,"UNKNOWN_FIXED_CHANNEL");
        string xpath="*[System[("+ids+") and TimeCreated[@SystemTime >= '"+Begin+"' and @SystemTime <= '"+End+"']]]";
        if(channel=="Security")xpath="*[System[(EventID=4688) and TimeCreated[@SystemTime >= '"+Begin+"' and @SystemTime <= '"+End+"']] and EventData[(Data[@Name='NewProcessId']='0x1e64' or Data[@Name='NewProcessId']='0x6e30' or Data[@Name='NewProcessId']='7780' or Data[@Name='NewProcessId']='28208')]]";
        if(channel=="Microsoft-Windows-TaskScheduler/Operational")xpath="*[System[("+ids+") and TimeCreated[@SystemTime >= '"+Begin+"' and @SystemTime <= '"+End+"']] and EventData[(Data[@Name='TaskName']='\\"+TaskName+"' or Data[@Name='TaskName']='"+TaskName+"')]]";
        return xpath;
    }
    public static Dictionary<string,object> Read(string channel) {
        var rows=new List<object>();var result=new Dictionary<string,object>{{"channel",channel},{"rows",rows},{"state","reading"}};
        var timer=Stopwatch.StartNew();int count=0;
        try {
            using(var reader=new EventLogReader(new EventLogQuery(channel,PathType.LogName,Query(channel)){ReverseDirection=false})) {
                while(true) {
                    Need(timer.Elapsed.TotalSeconds<20,"QUERY_TIME_BUDGET");
                    var entry=reader.ReadEvent(TimeSpan.FromMilliseconds(Math.Max(1,Math.Min(5000,20000-timer.Elapsed.TotalMilliseconds))));
                    if(entry==null)break;
                    using(entry){Need(++count<=128,"QUERY_EVENT_LIMIT");var safe=Parse(channel,entry.Id,entry.RecordId,entry.TimeCreated,entry.ToXml());if(safe!=null)rows.Add(safe);}
                }
            }
            result["state"]=rows.Count==0?"no_matching_records_not_proof_of_absence":"read";
        } catch(Exception e){result["state"]="partial_or_unavailable";result["error_type"]=e.GetType().Name;result["hresult"]=e.HResult.ToString("X8");if(e is EvidenceLimit)result["reason"]=e.Message;}
        result["examined"]=count;result["seconds"]=timer.Elapsed.TotalSeconds;return result;
    }
    public static void PlainOutput(string folder) {
        for(string p=Path.GetFullPath(folder);!string.IsNullOrEmpty(p);p=Path.GetDirectoryName(p))
            Need((File.GetAttributes(p)&FileAttributes.ReparsePoint)==0,"REPORT_PATH_REPARSE");
    }
    public static int Main(string[] args) {
        Console.OutputEncoding=new UTF8Encoding(false);
        var report=new Dictionary<string,object>{{"format",1},{"tool","GuardDesk LAB01 incident evidence 002"},{"incident_begin_utc",Begin},{"incident_end_utc",End},{"read_only",true},{"settings_changed",false},{"agent_executed",false},{"network_requests",false},{"result","REVIEW_REQUIRED"}};
        try {
            Need(args.Length==1&&args[0]=="--collect","USAGE_COLLECT_ONLY");
            Need(Environment.MachineName.Equals("LAB01",StringComparison.OrdinalIgnoreCase),"LAB01_ONLY");
            using(var id=WindowsIdentity.GetCurrent())Need(new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator),"ADMINISTRATOR_REQUIRED");
            var channels=new List<object>();report["channels"]=channels;
            foreach(string channel in new[]{"Microsoft-Windows-Windows Defender/Operational","Security","Microsoft-Windows-TaskScheduler/Operational"}) {
                Console.WriteLine("Reading fixed incident window: "+channel);channels.Add(Read(channel));
            }
            report["result"]="EVIDENCE_COLLECTED_REVIEW_REQUIRED";
        }catch(Exception e){report["error_type"]=e.GetType().Name;report["hresult"]=e.HResult.ToString("X8");if(e is EvidenceLimit)report["reason"]=e.Message;}
        try {
            string root=AppDomain.CurrentDomain.BaseDirectory;PlainOutput(root);
            string file=Path.Combine(root,"LAB01-Incident-"+Guid.NewGuid().ToString("N")+".json");
            using(var stream=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None))using(var writer=new StreamWriter(stream,new UTF8Encoding(false)))writer.Write(Json().Serialize(report));
            Console.WriteLine("Report="+file);Console.WriteLine("Result="+report["result"]);
        }catch(Exception e){Console.WriteLine("REPORT_WRITE_FAILED="+e.GetType().Name);return 1;}
        return (string)report["result"]=="EVIDENCE_COLLECTED_REVIEW_REQUIRED"?0:1;
    }
}}
