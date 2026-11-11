// Explicit operator setup for this exact internal management payload.
// No process/service/task, policy, owner, database or file-content changes.
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;

internal static class CenterSourcePrepare {
    const uint WriteSource=0x500D0156,WriteParent=WriteSource & ~4u;
    static readonly string Users="S-1-5-32-545";
    static readonly HashSet<string> Trusted=new HashSet<string>{"S-1-5-18","S-1-5-32-544","S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",WindowsIdentity.GetCurrent().User.Value};
    static readonly HashSet<string> Outer=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"GuardDesk","Setup-Management.cmd","BUILD-INFO.json","README-Management.txt","SHA256SUMS.txt","GuardDeskCenterPrepare.exe"};
    static readonly List<string> Log=new List<string>();
    static string Full(string value){
        string full=Path.GetFullPath(value);
        if(full.StartsWith("\\\\") || String.Equals(full.TrimEnd('\\'),Path.GetPathRoot(full).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new IOException("LOCAL_PACKAGE_FOLDER_REQUIRED_NOT_DRIVE_ROOT");
        return full.TrimEnd(Path.DirectorySeparatorChar);
    }
    static bool IsDirectory(string path){return (File.GetAttributes(path)&FileAttributes.Directory)!=0;}
    static void Plain(string path){
        for(string p=path;!String.IsNullOrEmpty(p);p=Path.GetDirectoryName(p))
            if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("REPARSE_PATH_REFUSED: "+p);
    }
    static FileSystemSecurity Read(string path){return IsDirectory(path)?(FileSystemSecurity)Directory.GetAccessControl(path,AccessControlSections.Access|AccessControlSections.Owner):File.GetAccessControl(path,AccessControlSections.Access|AccessControlSections.Owner);}
    static void Write(string path,FileSystemSecurity value){if(IsDirectory(path))Directory.SetAccessControl(path,(DirectorySecurity)value);else File.SetAccessControl(path,(FileSecurity)value);}
    static bool NeedsRepair(string path,FileSystemSecurity security,bool parent){
        if(!Trusted.Contains(security.GetOwner(typeof(SecurityIdentifier)).Value))throw new UnauthorizedAccessException("OWNER_NOT_CURRENT_SERVER_ACCOUNT: "+path);
        bool needed=false;
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier))){
            if(rule.AccessControlType!=AccessControlType.Allow || (rule.PropagationFlags&PropagationFlags.InheritOnly)!=0)continue;
            if((((uint)rule.FileSystemRights)&(parent?WriteParent:WriteSource))==0 || Trusted.Contains(rule.IdentityReference.Value))continue;
            if(rule.IdentityReference.Value!=Users)throw new UnauthorizedAccessException("OTHER_UNTRUSTED_WRITE_REQUIRES_REVIEW: "+path);
            // This installer addresses the observed WD/AD grants only. Rights
            // that permit replacement/security changes introduce a different
            // race boundary and must never be silently normalized here.
            if((((uint)rule.FileSystemRights)&WriteSource&~6u)!=0)throw new UnauthorizedAccessException("USERS_REPLACEMENT_OR_OTHER_WRITE_REQUIRES_REVIEW: "+path);
            needed=true;
        }
        return needed;
    }
    static Dictionary<string,string> Expected(){
        var result=new Dictionary<string,string>(StringComparer.Ordinal);
        using(var reader=new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream("center-files"),Encoding.UTF8)){
            string line;while((line=reader.ReadLine())!=null){
                if(line.Length<67 || line[64]!=' ')throw new IOException("EMBEDDED_MANIFEST_INVALID");
                string name=line.Substring(65);if(name.StartsWith("/") || name.Contains("\\") || name.Split('/').Any(x=>x==".." || x=="." || x==""))throw new IOException("EMBEDDED_PATH_INVALID");
                result.Add(name,line.Substring(0,64));
            }
        }
        if(result.Count<3 || result.Count>5000 || !result.ContainsKey("GuardDesk.exe") || !result.ContainsKey("_internal/agent-release.json"))throw new IOException("EMBEDDED_MANIFEST_INVALID");
        return result;
    }
    static List<string> Verify(string root,Dictionary<string,string> expected){
        Plain(root);if(!Directory.Exists(root))throw new IOException("PACKAGE_ROOT_REQUIRED");
        foreach(string item in Directory.GetFileSystemEntries(root)){
            Plain(item);string name=Path.GetFileName(item);
            if(!Outer.Contains(name) || (name=="GuardDesk")!=IsDirectory(item))throw new IOException("UNEXPECTED_PACKAGE_ROOT_ENTRY: "+name);
        }
        string source=Path.Combine(root,"GuardDesk");if(!Directory.Exists(source))throw new IOException("COMPLETE_MANAGEMENT_PACKAGE_REQUIRED");
        var paths=new List<string>{root};var pending=new Stack<string>();pending.Push(source);var found=new HashSet<string>(StringComparer.Ordinal);long total=0;
        while(pending.Count>0){
            string path=pending.Pop();Plain(path);paths.Add(path);if(paths.Count>10000)throw new IOException("SOURCE_TOO_LARGE");
            if(IsDirectory(path)){foreach(string child in Directory.GetFileSystemEntries(path))pending.Push(child);continue;}
            string name=path.Substring(source.Length+1).Replace('\\','/');string hash;
            if(!expected.TryGetValue(name,out hash))throw new IOException("UNEXPECTED_PROGRAM_FILE: "+name);
            using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))using(var digest=SHA256.Create()){
                if(stream.Length>512L*1024*1024 || (total+=stream.Length)>512L*1024*1024)throw new IOException("PROGRAM_BYTES_LIMIT_EXCEEDED");
                if(BitConverter.ToString(digest.ComputeHash(stream)).Replace("-","").ToLowerInvariant()!=hash)throw new IOException("PROGRAM_HASH_MISMATCH: "+name);
            }
            found.Add(name);
        }
        if(!found.SetEquals(expected.Keys))throw new IOException("PROGRAM_FILES_MISSING");
        return paths;
    }
    static void Restore(string path,string sddl){
        FileSystemSecurity security=IsDirectory(path)?(FileSystemSecurity)new DirectorySecurity():new FileSecurity();
        security.SetSecurityDescriptorSddlForm(sddl,AccessControlSections.Access);Write(path,security);
    }
    static int Main(string[] args){
        Console.OutputEncoding=new UTF8Encoding(false);var changed=new List<KeyValuePair<string,string>>();
        string report=Path.Combine(Path.GetTempPath(),"GuardDesk-Center-Permissions-"+Guid.NewGuid().ToString("N")+".txt");
        int code=1;
        try{
            if(args.Length!=2 || (args[0]!="--check-only" && args[0]!="--prepare"))throw new ArgumentException("Use --check-only or --prepare with the complete management package folder");
            string root=Full(args[1]);var expected=Expected();var paths=Verify(root,expected);
            Log.Add("Root="+root);Log.Add("CurrentServerAccountSID="+WindowsIdentity.GetCurrent().User.Value);Log.Add("ProgramHashesVerified="+expected.Count);
            var needs=new List<string>();
            foreach(string path in paths)if(NeedsRepair(path,Read(path),path==root))needs.Add(path);
            if(args[0]=="--check-only" && needs.Count>0){Log.Add("Result=SOURCE_ACL_BLOCKED_USERS_WRITE");code=2;}
            else{
                if(args[0]=="--prepare")foreach(string path in paths){
                    Plain(path);var security=Read(path);if(!NeedsRepair(path,security,path==root))continue;
                    string owner=security.GetOwner(typeof(SecurityIdentifier)).Value;
                    string before=security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                    // .NET keeps inherited ACE flags in its in-memory ACL after
                    // SetAccessRuleProtection(true,true). RemoveAccessRuleSpecific
                    // does not remove those inherited entries. Persist protection,
                    // then read the now-explicit rules before narrowing Users.
                    // Record rollback BEFORE this first write, not only the last.
                    changed.Add(new KeyValuePair<string,string>(path,before));
                    security.SetAccessRuleProtection(true,true);Write(path,security);
                    security=Read(path);
                    if(Read(path).GetOwner(typeof(SecurityIdentifier)).Value!=owner)throw new IOException("OWNER_CHANGED_UNEXPECTEDLY");
                    foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                        if(rule.AccessControlType==AccessControlType.Allow && rule.IdentityReference.Value==Users && (((uint)rule.FileSystemRights)&WriteSource)!=0)security.RemoveAccessRuleSpecific(rule);
                    // Only read/execute for Users; preserve every other grant,
                    // deny and original owner. No new privileged write grant.
                    var inherit=IsDirectory(path)?InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit:InheritanceFlags.None;
                    security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(Users),FileSystemRights.ReadAndExecute,inherit,PropagationFlags.None,AccessControlType.Allow));
                    Write(path,security);
                    if(Read(path).GetOwner(typeof(SecurityIdentifier)).Value!=owner)throw new IOException("OWNER_CHANGED_UNEXPECTEDLY");
                    Log.Add("ACL-BEFORE "+path+" "+before);
                }
                paths=Verify(root,expected);
                foreach(string path in paths)if(NeedsRepair(path,Read(path),path==root))throw new IOException("ACL_READBACK_FAILED: "+path);
                Log.Add("ACLObjectsChanged="+changed.Count);Log.Add("ProgramHashesUnchanged=true");
                Log.Add("AgentMISDatabaseDefenderOwnerChanged=false");Log.Add("Result=PROGRAM_SOURCE_READY");code=0;
            }
        }catch(Exception error){
            Log.Add("Error="+error.GetType().Name+": "+error.Message);
            if(changed.Count>0){bool restored=true;for(int i=changed.Count-1;i>=0;--i)try{Restore(changed[i].Key,changed[i].Value);}catch(Exception restore){restored=false;Log.Add("RollbackError="+restore.Message);}
                Log.Add("OriginalDACLRestoreSucceeded="+restored);}
            Log.Add("Result=STOPPED_NO_SETUP");code=1;
        }
        try{File.WriteAllLines(report,Log,new UTF8Encoding(false));}catch(Exception error){Console.WriteLine("ReportWriteError="+error.GetType().Name);code=1;}
        foreach(string line in Log.Where(x=>!x.StartsWith("ACL-BEFORE ")))Console.WriteLine(line);
        Console.WriteLine("Report="+report);Console.WriteLine("ExitCode="+code);
        return code;
    }
}
