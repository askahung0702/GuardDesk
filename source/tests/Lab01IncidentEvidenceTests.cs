using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using GuardDeskIncident;
class IncidentTests {
    static List<string> passed=new List<string>();
    static void Test(string n,Action a){a();passed.Add(n);}
    static void Need(bool v){if(!v)throw new Exception("Assertion failed");}
    static void Reject(Action a,string code){try{a();}catch(EvidenceLimit e){Need(e.Message==code);return;}throw new Exception("Expected "+code);}
    static string Field(string n,string v){return "<Data Name='"+n+"'>"+System.Security.SecurityElement.Escape(v)+"</Data>";}
    static string Xml(string x){return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData>"+x+"</EventData></Event>";}
    static string Agent=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"GuardDeskPilot\USBControl\GuardDesk.exe");
    static DateTime Start=DateTime.FromFileTimeUtc(Evidence.Starts[28208]);
    static string Security(string pid="0x6e30",string image=null,string command=null){return Xml(Field("NewProcessId",pid)+Field("NewProcessName",image??Agent)+Field("ProcessId","0x1e64")+Field("ParentProcessName",Agent)+Field("CommandLine",command??("\""+Agent+"\" machine-session --parent 7780 --secret PRIVATE_SECRET"))+Field("SubjectUserName","PRIVATE_ACCOUNT"));}
    public static int Main(string[] args){
        string root=Path.GetFullPath(args[0]);Directory.CreateDirectory(root);
        try {
            Test("reported PID hex conversion",()=>Need(Evidence.Pid("0x6e30")==28208&&Evidence.Pid("0x1e64")==7780));
            Test("invalid or overflowing PID rejected",()=>{foreach(string x in new[]{"-1","0x100000000","4294967296","TRUE","1 secret"})Need(Evidence.Pid(x)==null);});
            Test("exact historical helper and parent metadata without command",()=>{var r=Evidence.Parse("Security",4688,1,Start,Security());Need((uint)r["pid"]==28208&&(uint)r["parent_pid"]==7780&&(string)r["role_from_fixed_command"]=="machine_session_helper"&&(bool)r["matches_reported_start_within_2_seconds"]);Need(!Evidence.Json().Serialize(r).Contains("PRIVATE"));});
            Test("PID reuse outside start tolerance not asserted",()=>Need(!(bool)Evidence.Parse("Security",4688,1,Start.AddSeconds(20),Security())["matches_reported_start_within_2_seconds"]));
            Test("unknown PID ignored",()=>Need(Evidence.Parse("Security",4688,1,Start,Security("0x99"))==null));
            Test("outside incident window ignored",()=>Need(Evidence.Parse("Security",4688,1,Start.AddHours(1),Security())==null));
            Test("event time required",()=>Reject(()=>Evidence.Parse("Security",4688,1,null,Security()),"EVENT_TIME_MISSING"));
            Test("known executable in unrelated private location not trusted",()=>Need((string)Evidence.Parse("Security",4688,1,Start,Security(image:@"C:\Users\PRIVATE\GuardDesk.exe"))["image_class"]=="other_or_unavailable_path_omitted"));
            Test("unknown command role remains unknown",()=>Need(Evidence.Role(Agent,"\""+Agent+"\" usb-worker-injected")=="unknown"));
            Test("command line prefix must match exact installed image",()=>Need(Evidence.Role(Agent,@"C:\Other.exe machine-session")=="unknown"));
            Test("native role recognized without argv retention",()=>Need(Evidence.Role(Agent,"\""+Agent+"\" usb-worker --config PRIVATE_SECRET")=="native_worker"));
            Test("missing command not fabricated",()=>Need(Evidence.Role(Agent,"")=="unknown"));
            Test("Defender observed resources preserved as classifications",()=>{string x=Xml(Field("Threat Name","Behavior:Win32/Execution.A!ml")+Field("Path",@"file: C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe; process: pid:28208,ProcessStart:134381583224646976; "+Evidence.TaskName)+Field("Detection ID","{10D0700D-B8A3-47AA-86C5-157931B7409B}"));var r=Evidence.Parse("Microsoft-Windows-Windows Defender/Operational",1116,4976,Start.AddSeconds(38),x);Need((bool)r["mentions_installed_agent"]&&(bool)r["mentions_exact_task"]&&r.ContainsKey("detection_id"));Need(((List<object>)r["process_references"]).Count==1);});
            Test("action not mistaken for successful remediation",()=>{var r=Evidence.Parse("Microsoft-Windows-Windows Defender/Operational",1117,4977,Start,Xml(Field("Path","GuardDesk")+Field("Error Code","0x80070005")));Need((bool)r["remediation_success_not_inferred"]);});
            Test("private event fields never exported",()=>{var r=Evidence.Parse("Microsoft-Windows-Windows Defender/Operational",1116,4976,Start,Xml(Field("Path",@"C:\Users\PRIVATE_SECRET\GuardDesk")+Field("Detection User","PRIVATE_USER")+Field("Process Name",@"C:\PRIVATE_BINARY.exe")));Need(!Evidence.Json().Serialize(r).Contains("PRIVATE"));});
            Test("unrelated Defender entry ignored",()=>Need(Evidence.Parse("Microsoft-Windows-Windows Defender/Operational",1116,1,Start,Xml(Field("Path","other")))==null));
            Test("exact task only",()=>{string c="Microsoft-Windows-TaskScheduler/Operational";Need(Evidence.Parse(c,200,1,Start,Xml(Field("TaskName","\\"+Evidence.TaskName)))!=null);Need(Evidence.Parse(c,200,1,Start,Xml(Field("TaskName","OtherTask")))==null);});
            Test("task action argv omitted",()=>{var r=Evidence.Parse("Microsoft-Windows-TaskScheduler/Operational",200,1,Start,Xml(Field("TaskName",Evidence.TaskName)+Field("ActionName","PRIVATE_SECRET")+Field("ProcessID","7780")));Need((uint)r["ProcessID"]==7780&&!Evidence.Json().Serialize(r).Contains("PRIVATE"));});
            Test("oversized event rejected",()=>Reject(()=>Evidence.Fields(new string('x',1048577)),"EVENT_SIZE_LIMIT"));
            Test("duplicate fields rejected",()=>Reject(()=>Evidence.Fields(Xml(Field("a","1")+Field("a","2"))),"DUPLICATE_EVENT_FIELD"));
            Test("field capacity enforced",()=>Reject(()=>Evidence.Fields(Xml(string.Join("",Enumerable.Range(0,129).Select(i=>Field("f"+i,"x"))))),"EVENT_FIELD_LIMIT"));
            Test("DTD and external entities refused",()=>{try{Evidence.Fields("<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///C:/secret'>]><a>&e;</a>");}catch(System.Xml.XmlException){return;}throw new Exception("DTD accepted");});
            Test("queries have fixed time bounds and fixed PIDs",()=>{string q=Evidence.Query("Security");Need(q.Contains(Evidence.Begin)&&q.Contains(Evidence.End)&&q.Contains("0x6e30")&&q.Contains("0x1e64"));});
            Test("unknown query channel rejected",()=>Reject(()=>Evidence.Query("Other"),"UNKNOWN_FIXED_CHANNEL"));
            Test("scheduler filtering occurs in query not only after enumeration",()=>{string q=Evidence.Query("Microsoft-Windows-TaskScheduler/Operational");Need(q.Contains("Data[@Name='TaskName']")&&q.Contains(Evidence.TaskName));});
            // Real EventLogReader syntax check on a local channel; count only,
            // never serialize unrelated event data, never enable a log/policy.
            Test("actual Windows query syntax",()=>{foreach(string c in new[]{"Security","Microsoft-Windows-Windows Defender/Operational","Microsoft-Windows-TaskScheduler/Operational"})using(var reader=new System.Diagnostics.Eventing.Reader.EventLogReader(new System.Diagnostics.Eventing.Reader.EventLogQuery("Application",System.Diagnostics.Eventing.Reader.PathType.LogName,Evidence.Query(c))))using(var e=reader.ReadEvent(TimeSpan.FromSeconds(5))){};});
            File.WriteAllText(Path.Combine(root,"tests.json"),Evidence.Json().Serialize(new{checks=passed.Count,passed=passed,LAB01_changed=false,company_event_contents_saved=false}));
            Console.WriteLine("Passed="+passed.Count);return 0;
        }catch(Exception e){File.WriteAllText(Path.Combine(root,"failure.txt"),e.ToString());Console.WriteLine(e);return 1;}
    }
}
