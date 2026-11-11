using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using GuardDeskMaintenance;
using D=GuardDeskMaintenance.Diagnostics;

class DiagnosticTests {
    static List<string> passed=new List<string>();
    static void Test(string name,Action test){test();passed.Add(name);}
    static void Need(bool value){if(!value)throw new Exception("Assertion failed");}
    static void Reject(Action test,string code){try{test();}catch(Review e){Need(e.Message==code);return;}throw new Exception("Expected "+code);}
    static string Xml(string fields){return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData>"+fields+"</EventData></Event>";}
    static string Field(string name,string value){return "<Data Name='"+name+"'>"+System.Security.SecurityElement.Escape(value)+"</Data>";}
    static Dictionary<string,object> Event(long id=4976){return D.Event(Xml(Field("Threat Name","Behavior:Win32/Execution.A!ml")+Field("Path",@"file: C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe; process: pid:7780,ProcessStart:134381583131634652")),1116,id,DateTime.UtcNow);}
    public static int Main(string[] args){
        string root=Path.GetFullPath(args[0]);Directory.CreateDirectory(root);
        try {
            Test("087 candidate held before any IO",()=>Reject(D.CandidateGate,"CANDIDATE_087_ON_HOLD_NO_RETRY"));
            foreach(var c in new[]{Tuple.Create(225,"ANTIMALWARE_FILE_ACCESS_BLOCKED"),Tuple.Create(226,"ANTIMALWARE_FILE_REMOVED"),Tuple.Create(5,"WINDOWS_ACCESS_DENIED"),Tuple.Create(2,"FILE_NOT_FOUND"),Tuple.Create(3,"DIRECTORY_NOT_FOUND"),Tuple.Create(32,"FILE_SHARING_VIOLATION"),Tuple.Create(1117,"WINDOWS_API_OR_IO_ERROR")})Test("HRESULT distinguishes "+c.Item1,()=>Need(D.ErrorCode(new IOException("PRIVATE_SECRET",unchecked((int)0x80070000)|c.Item1))==c.Item2));
            Test("review codes preserved",()=>Need(D.ErrorCode(new Review("DEFENDER_EVENT_REVIEW_REQUIRED"))=="DEFENDER_EVENT_REVIEW_REQUIRED"));
            Test("native process launch virus error distinguished",()=>Need(D.ErrorCode(new System.ComponentModel.Win32Exception(225,"PRIVATE_SECRET"))=="ANTIMALWARE_FILE_ACCESS_BLOCKED"));
            Test("native access denied distinguished",()=>Need(D.ErrorCode(new System.ComponentModel.Win32Exception(5,"PRIVATE_SECRET"))=="WINDOWS_ACCESS_DENIED"));
            Test("invalid native code not reinterpreted",()=>Need(D.ErrorCode(new System.ComponentModel.Win32Exception(-1,"PRIVATE_SECRET"))=="WINDOWS_API_OR_IO_ERROR"));
            Test("actual field threat and PID retained",()=>{var row=Event();Need((string)row["threat_name"]=="Behavior:Win32/Execution.A!ml"&&(bool)row["mentions_installed_agent"]);string s=Checks.Serializer(10000).Serialize(row);Need(s.Contains("7780")&&s.Contains("134381583131634652")&&!s.Contains("Program Files"));});
            Test("detection does not imply remediation",()=>Need(!(bool)Event()["remediation_confirmed"]));
            Test("action event does not imply success",()=>{var r=D.Event(Xml(Field("Path","GuardDesk")+Field("Action ID","2")+Field("Error Code","0x80070005")),1117,9,null);Need(!(bool)r["remediation_confirmed"]&&(string)r["Error Code"]=="0x80070005");});
            Test("private event paths and arbitrary fields omitted",()=>{var r=D.Event(Xml(Field("Path",@"C:\Users\PRIVATE_SECRET\GuardDesk\config.json")+Field("Detection User","PRIVATE_ACCOUNT")+Field("CommandLine","PRIVATE_TOKEN")),1116,10,null);string s=Checks.Serializer(10000).Serialize(r);Need(!s.Contains("PRIVATE"));});
            Test("invalid threat field omitted",()=>Need(!D.Event(Xml(Field("Threat Name","secret\nunsafe")+Field("Path","GuardDesk")),1116,11,null).ContainsKey("threat_name")));
            Test("unrelated event ignored",()=>Need(D.Event(Xml(Field("Path","OtherProduct")),1116,10,null)==null));
            Test("duplicate fields rejected",()=>Reject(()=>D.Event(Xml(Field("Path","GuardDesk")+Field("Path","other")),1116,1,null),"EVENT_DUPLICATE_FIELD"));
            Test("oversized XML rejected",()=>Reject(()=>D.Event(new string('x',1048577),1116,1,null),"EVENT_SIZE_LIMIT"));
            Test("XML DTD rejected",()=>{try{D.Event("<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///C:/secret'>]><a>GuardDesk&e;</a>",1116,1,null);}catch(System.Xml.XmlException){return;}throw new Exception("DTD allowed");});
            Test("too many fields rejected",()=>Reject(()=>D.Event(Xml(string.Join("",Enumerable.Range(0,129).Select(i=>Field("f"+i,"GuardDesk")))),1116,1,null),"EVENT_FIELD_LIMIT"));
            Test("event deduplicates and empty later result cannot erase",()=>{var kept=new List<object>();D.MergeEvents(kept,new List<object>{Event()});D.MergeEvents(kept,new List<object>{Event()});D.MergeEvents(kept,new List<object>());Need(kept.Count==1);});
            Test("evidence limit preserves previous rows",()=>{var kept=Enumerable.Range(1,127).Select(i=>(object)Event(i)).ToList();Reject(()=>D.MergeEvents(kept,new List<object>{Event(128)}),"EVENT_EVIDENCE_LIMIT");Need(kept.Count==127);});
            string image=@"C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe";
            var raw=new Dictionary<string,object>{{"ExecutablePath",image},{"ProcessId",7780L},{"ParentProcessId",500L},{"SessionId",0L},{"CreationDate","20261103134513.163465+480"},{"CommandLine","PRIVATE_TOKEN"}};
            Test("process metadata preserves identity without inferring role",()=>{var r=D.Process(raw,image);Need((string)r["functional_role"]=="unknown"&&!r.ContainsKey("CommandLine")&&r.ContainsKey("CreationDate"));});
            Test("same name different image ignored",()=>Need(D.Process(raw,@"C:\Other\GuardDesk.exe")==null));
            Test("invalid creation time rejected",()=>{var r=new Dictionary<string,object>(raw);r["CreationDate"]="PRIVATE_TOKEN";Reject(()=>D.Process(r,image),"PROCESS_CREATION_TIME_INVALID");});
            Test("fractional PID rejected",()=>{var r=new Dictionary<string,object>(raw);r["ProcessId"]=1.5;Reject(()=>D.Process(r,image),"PROCESS_METADATA_INVALID");});
            Test("actual owned WMI process metadata",()=>{
                using(var self=System.Diagnostics.Process.GetCurrentProcess()) {
                    var r=WindowsApi.Query(@"root\cimv2","SELECT ExecutablePath,ProcessId,ParentProcessId,SessionId,CreationDate FROM Win32_Process WHERE ProcessId="+self.Id,new[]{"ExecutablePath","ProcessId","ParentProcessId","SessionId","CreationDate"});
                    var safe=D.Process(r,self.MainModule.FileName);Need(safe!=null&&(double)safe["ProcessId"]==self.Id&&safe.ContainsKey("CreationDate"));
                }
            });
            Test("real locked inventory retains relative failing entry",()=>{
                string dir=Path.Combine(root,"owned-inventory");Directory.CreateDirectory(dir);string p=Path.Combine(dir,"owned.bin");File.WriteAllText(p,"owned");var manifest=new Dictionary<string,object>{{"owned.bin",Checks.Hash(p)}};
                using(var locked=new FileStream(p,FileMode.Open,FileAccess.ReadWrite,FileShare.None))try{Checks.Inventory(dir,manifest);}catch(IOException e){Need(D.ErrorCode(e)=="FILE_SHARING_VIOLATION"&&(string)e.Data["guarddesk_payload_entry"]=="owned.bin");return;}
                throw new Exception("Expected sharing violation");
            });
            File.WriteAllText(Path.Combine(root,"tests.json"),Checks.Serializer(100000).Serialize(new{checks=passed.Count,passed=passed,actual_endpoint_modified=false,defender_detection_triggered=false}));
            Console.WriteLine("Passed="+passed.Count);return 0;
        }catch(Exception e){File.WriteAllText(Path.Combine(root,"failure.txt"),e.ToString());Console.WriteLine(e);return 1;}
    }
}
