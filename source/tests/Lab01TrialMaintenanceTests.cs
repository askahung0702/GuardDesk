using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Security.Cryptography;
using GuardDeskMaintenance;

class OwnedSteps:ITrialSteps {
    public List<string> Called=new List<string>();public string Failure;
    void Hit(string s){Called.Add(s);if(s==Failure)throw new Review("OWNED_FAILURE");}
    public void Check(){Hit("check");}public void Recover(){Hit("recover");}public void Install(){Hit("install");}public void Observe(){Hit("observe");}
}
class Tests {
    static int count;static List<string> passed=new List<string>();
    static void Test(string label,Action action){action();passed.Add(label);count++;}
    static void Reject(Action action,string code){try{action();}catch(Review e){if(e.Message==code)return;throw;}throw new Exception("Expected "+code);}
    static Dictionary<string,object> Identity(){return new Dictionary<string,object>{{"device_id",RealTrial.Device},{"server",RealTrial.Server},{"install_profile","remote-only-trial-v1"},{"version","0.4.85"}};}
    static Dictionary<string,object> Health(){return new Dictionary<string,object>{{"version","0.4.87"},{"pid",123},{"time",995.0}};}
    public static int Main(string[] args){
        string root=Path.GetFullPath(args[0]);Directory.CreateDirectory(root);
        try{
            foreach(string failure in new[]{"check","recover","install","observe",""})Test("orchestration stops at "+failure,()=>{
                var s=new OwnedSteps{Failure=failure};var stages=new List<string>();
                if(failure!="")Reject(()=>TrialSequence.Run(s,stages.Add),"OWNED_FAILURE");else TrialSequence.Run(s,stages.Add);
                string[] all={"check","recover","install","observe"};int expected=failure==""?4:Array.IndexOf(all,failure)+1;
                Checks.Need(s.Called.SequenceEqual(all.Take(expected))&&stages.Count==expected,"WRONG_FLOW");
            });
            Test("valid legacy and final marker",()=>{var d=Identity();Checks.Identity(d,true,false);d["version"]="0.4.86";Checks.Identity(d,true,false);d["version"]="0.4.87";Checks.Identity(d,true,true);});
            foreach(string key in new[]{"device_id","server","install_profile"})Test("reject marker "+key,()=>{var d=Identity();d[key]="wrong";Reject(()=>Checks.Identity(d,true,false),"TRIAL_IDENTITY_MISMATCH");});
            Test("already installed marker stops rerun",()=>{var d=Identity();d["version"]="0.4.87";Reject(()=>Checks.Identity(d,true,false),"MACHINE_VERSION_MISMATCH");});
            Test("current health accepted",()=>Checks.Need(Checks.Health(Health(),1000,123)==123,"PID"));
            Test("stale health rejected",()=>Reject(()=>Checks.Health(Health(),1020,0),"HEALTH_STALE"));
            Test("future health rejected",()=>Reject(()=>Checks.Health(Health(),980,0),"HEALTH_STALE"));
            Test("restarted worker rejected",()=>Reject(()=>Checks.Health(Health(),1000,124),"WORKER_RESTARTED"));
            foreach(object pid in new object[]{0,-1,1.5,"123",true,2147483648L})Test("invalid pid "+pid,()=>{var h=Health();h["pid"]=pid;try{Checks.Health(h,1000,0);}catch(Review){return;}throw new Exception("PID accepted");});
            Test("wrong health version",()=>{var h=Health();h["version"]="0.4.86";Reject(()=>Checks.Health(h,1000,0),"HEALTH_VERSION_PID_MISMATCH");});
            Test("failure metadata omits secrets and unknown strings",()=>{var d=Identity();d["token"]="PRIVATE_SECRET";d["phase"]="PRIVATE_SECRET";d["state"]="entered";d["pid"]=100;var safe=RealTrial.Metadata(d);Checks.Need(safe.Count==3&&!Checks.Serializer(10000).Serialize(safe).Contains("PRIVATE_SECRET"),"METADATA_LEAK");});
            Test("transaction evidence whitelist",()=>{var d=new Dictionary<string,object>{{"id","58c600df5db6cf7f"},{"phase","register_tasks"},{"version","0.4.86"}};Checks.Need(RealTrial.Metadata(d).Count==3,"MISSING_TRANSACTION_EVIDENCE");});
            foreach(string path in new[]{"../escape","a/../escape","C:/escape","a:b","a//b","a./b","a /b","a\n"})Test("invalid relative path "+path,()=>Reject(()=>Checks.Child(root,path),"INVALID_PAYLOAD_PATH"));
            Test("valid unicode nested path",()=>Checks.Need(Checks.Child(root,"資料夾/file.txt").StartsWith(root),"PATH"));
            string json=Path.Combine(root,"owned.json");File.WriteAllText(json,"{\"owned\":true}");
            Test("bounded valid JSON",()=>Checks.Need((bool)Checks.Json(json,65536)["owned"],"JSON"));
            Test("zero bound",()=>Reject(()=>Checks.Json(json,0),"INVALID_JSON_BOUND"));
            Test("oversized bound",()=>Reject(()=>Checks.Json(json,4194305),"INVALID_JSON_BOUND"));
            Test("oversized file",()=>{File.WriteAllText(json,new string('x',70000));Reject(()=>Checks.Json(json,65536),"STATE_SIZE_LIMIT");});
            Test("JSON error hides secret",()=>{File.WriteAllText(json,"PRIVATE_SECRET {");Reject(()=>Checks.Json(json,65536),"INVALID_JSON_CONTENTS_OMITTED");});
            Test("JSON arrays rejected",()=>{File.WriteAllText(json,"[]");Reject(()=>Checks.Json(json,65536),"JSON_OBJECT_REQUIRED");});
            string inventory=Path.Combine(root,"inventory");Directory.CreateDirectory(inventory);string file=Path.Combine(inventory,"program.bin");File.WriteAllText(file,"ORIGINAL");
            var manifest=new Dictionary<string,object>{{"program.bin",Checks.Hash(file)}};
            Test("exact file inventory",()=>Checks.Inventory(inventory,manifest));
            Test("changed bytes rejected",()=>{File.WriteAllText(file,"CHANGED");Reject(()=>Checks.Inventory(inventory,manifest),"PAYLOAD_HASH_MISMATCH");File.WriteAllText(file,"ORIGINAL");});
            Test("extra file rejected",()=>{string extra=Path.Combine(inventory,"extra");File.WriteAllText(extra,"x");Reject(()=>Checks.Inventory(inventory,manifest),"INVENTORY_MISMATCH");File.Move(extra,Path.Combine(root,"kept-extra"));});
            Test("manifest traversal rejected",()=>{var m=new Dictionary<string,object>{{"../program.bin",Checks.Hash(file)}};Reject(()=>Checks.Inventory(inventory,m),"INVALID_PAYLOAD_PATH");});
            Test("archive inherited exclusion text",()=>Checks.Need(Checks.ExclusionVerdict(1,"Path is not excluded.\r\n")=="not_excluded","SCOPE"));
            Test("excluded verdict",()=>Checks.Need(Checks.ExclusionVerdict(0,"Path is excluded.")=="excluded","SCOPE"));
            foreach(var pair in new[]{Tuple.Create(0,"is not excluded."),Tuple.Create(1,"Access denied"),Tuple.Create(5,"is not excluded."),Tuple.Create(1,"is excluded. is not excluded."),Tuple.Create(0,"")})Test("ambiguous scope "+pair.Item1+pair.Item2,()=>Checks.Need(Checks.ExclusionVerdict(pair.Item1,pair.Item2)=="unknown","SCOPE"));
            Test("explicit clean scan",()=>Checks.CleanScan(0,"Scan found no threats."));
            Test("scan zero alone rejected",()=>Reject(()=>Checks.CleanScan(0,"Scan ended"),"SCAN_REVIEW_REQUIRED"));
            Test("failed scan rejected",()=>Reject(()=>Checks.CleanScan(2,"found no threats."),"SCAN_REVIEW_REQUIRED"));
            Test("safe quoted filename",()=>Checks.Need(Checks.Quote("C:\\測試 1\\app.exe")=="\"C:\\測試 1\\app.exe\"","QUOTE"));
            foreach(string a in new[]{"a\"b","a\nb","C:\\"})Test("bad argument rejected",()=>Reject(()=>Checks.Quote(a),"INVALID_FIXED_ARGUMENT"));
            Test("external XML entities refused",()=>{try{Checks.Xml("<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///C:/secret'>]><a>&e;</a>");}catch(System.Xml.XmlException){return;}throw new Exception("DTD allowed");});
            Test("trusted Microsoft Defender executable",()=>WindowsApi.MicrosoftSigned(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpCmdRun.exe"));
            Test("unsigned coordinator refused as Microsoft",()=>Reject(()=>WindowsApi.MicrosoftSigned(typeof(Checks).Assembly.Location),"DEFENDER_SIGNATURE_NOT_VALID"));
            var result=new Dictionary<string,object>{{"checks",count},{"passed",passed},{"actual_agent_install",false},{"settings_changed",false},{"assembly",typeof(Checks).Assembly.Location},{"assembly_sha256",Checks.Hash(typeof(Checks).Assembly.Location)}};
            File.WriteAllText(Path.Combine(root,"tests.json"),Checks.Serializer(1048576).Serialize(result));Console.WriteLine("Passed="+count);return 0;
        }catch(Exception e){File.WriteAllText(Path.Combine(root,"failure.txt"),e.ToString());Console.WriteLine(e);return 1;}
    }
}
